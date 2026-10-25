package org.shem.mailbox;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.InputStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.shem.common.FaultInjector;
import org.shem.common.OpaqueId;
import org.shem.crypto.Argon2idKdf;
import org.shem.crypto.CryptoException;
import org.shem.crypto.KdfAdmission;
import org.shem.crypto.KeySlot;
import org.shem.crypto.Keyring;
import org.shem.crypto.Secret;
import org.shem.crypto.SlotKind;
import org.shem.crypto.SymmetricKey;
import org.shem.delivery.DeliveryRequest;
import org.shem.delivery.MessageSource;
import org.shem.delivery.RecipientDelivery;
import org.shem.delivery.RecipientOutcome;
import org.shem.identity.Account;
import org.shem.identity.AccountState;
import org.shem.identity.EmailAddress;
import org.shem.identity.RecipientRoute;
import org.shem.store.DeliveryTarget;
import org.shem.store.PlaintextScan;
import org.shem.store.ReceiptStore;
import org.shem.store.SpecialUse;
import org.shem.store.metadata.Flags;
import org.shem.store.metadata.Folder;
import org.shem.store.metadata.MessageKey;
import org.shem.store.metadata.MessageRecord;

/** Phase 2 vertical slice: locked delivery, enrollment, unlock, import, read, restart. */
class MailboxVerticalSliceTest {
  private static final String PASSWORD = "correct horse battery staple";
  private static final InetAddress CLIENT = InetAddress.getLoopbackAddress();
  @TempDir Path dir;
  private TestMailServer server;
  private Account alice;
  private String bootstrap;

  @BeforeEach
  void setUp() throws Exception {
    server = new TestMailServer(dir, Clock.systemUTC(), FaultInjector.NONE, Duration.ZERO);
    server.identity.createDomain("example.org");
    MailboxProvisioning.Provisioned provisioned =
        server.provisioning.provision(
            EmailAddress.parse("alice@example.org"), 0, Duration.ofDays(1));
    alice = provisioned.account();
    try (Secret secret = provisioned.bootstrapPassword()) {
      bootstrap = new String(secret.exposeCopy(), StandardCharsets.UTF_8);
    }
  }

  @AfterEach
  void tearDown() {
    server.close();
  }

  private static byte[] message(String marker) {
    return ("From: Bob <bob@example.net>\r\nTo: alice@example.org\r\nSubject: "
            + marker
            + "\r\nMessage-ID: <"
            + marker
            + "@example.net>\r\n\r\nHello "
            + marker
            + "\r\nsecond line\r\n")
        .getBytes(StandardCharsets.US_ASCII);
  }

  private RecipientOutcome deliver(String marker) throws Exception {
    RecipientRoute route = server.identity.resolveRecipient(alice.address()).get(0);
    List<RecipientOutcome> outcomes =
        server.delivery.deliver(
            new DeliveryRequest(
                OpaqueId.random(TestMailServer.RANDOM),
                List.of(
                    new RecipientDelivery(
                        route,
                        "alice@example.org",
                        new DeliveryTarget.Role(SpecialUse.INBOX),
                        0,
                        List.of(),
                        List.of())),
                MessageSource.ofBytes(message(marker)),
                System.currentTimeMillis(),
                "bob@example.net"));
    assertThat(outcomes.get(0)).isInstanceOf(RecipientOutcome.Delivered.class);
    return outcomes.get(0);
  }

  private MailboxLease enroll() throws Exception {
    try (MailboxLease enrollment =
        server.sessions.authenticate("alice@example.org", bootstrap, CLIENT, Capability.ENROLL)) {
      server.lifecycle.enroll(enrollment, PASSWORD);
    }
    return server.sessions.authenticate(
        "alice@example.org", PASSWORD, CLIENT, Capability.MAIL_ACCESS);
  }

  private static List<String> inboxSubjects(MailboxLease lease) throws Exception {
    Folder inbox = lease.read(v -> v.folderByRole(SpecialUse.INBOX).orElseThrow());
    List<MessageRecord> records = new java.util.ArrayList<>();
    lease.read(
        v -> {
          v.forEachMessage(inbox.folderId(), (uid, r) -> records.add(r));
          return null;
        });
    List<String> subjects = new java.util.ArrayList<>();
    for (MessageRecord r : records) {
      try (InputStream in = lease.openMessage(r)) {
        String text = new String(in.readAllBytes(), StandardCharsets.US_ASCII);
        subjects.add(
            text.substring(
                text.indexOf("Subject: ") + 9, text.indexOf("\r\n", text.indexOf("Subject: "))));
      }
    }
    return subjects;
  }

  @Test
  void lockedDeliveryEnrollmentUnlockImportAndRead() throws Exception {
    deliver("PRE-ENROLLMENT-MARKER");
    assertThat(server.registry.isUnlocked(alice.mailboxId())).isFalse();

    // Bootstrap credentials only allow enrollment.
    assertThatThrownBy(
            () ->
                server.sessions.authenticate(
                    "alice@example.org", bootstrap, CLIENT, Capability.MAIL_ACCESS))
        .extracting(e -> ((AuthenticationException) e).reason())
        .isEqualTo(AuthenticationException.Reason.NOT_PERMITTED);

    try (MailboxLease lease = enroll()) {
      Account enrolled = server.identity.account(alice.mailboxId()).orElseThrow();
      assertThat(enrolled.state()).isEqualTo(AccountState.ACTIVE);
      assertThat(enrolled.publicKey().keyVersion()).isEqualTo(2);
      assertThat(enrolled.publicKey().fingerprint()).isNotEqualTo(alice.publicKey().fingerprint());
      assertThat(inboxSubjects(lease)).containsExactly("PRE-ENROLLMENT-MARKER");

      // Delivery while unlocked is imported in the background.
      deliver("WHILE-UNLOCKED-MARKER");
      awaitInbox(lease, 2);
      assertThat(inboxSubjects(lease))
          .containsExactly("PRE-ENROLLMENT-MARKER", "WHILE-UNLOCKED-MARKER");
    }
    assertThat(server.registry.isUnlocked(alice.mailboxId())).isFalse();

    // The bootstrap credential is gone.
    assertThatThrownBy(
            () ->
                server.sessions.authenticate(
                    "alice@example.org", bootstrap, CLIENT, Capability.ENROLL))
        .extracting(e -> ((AuthenticationException) e).reason())
        .isEqualTo(AuthenticationException.Reason.INVALID);

    deliver("WHILE-LOCKED-MARKER");
    PlaintextScan.assertNoMarkers(
        dir, "MARKER", "bob@example.net", "Hello", "Subject", "INBOX", "Junk", PASSWORD);

    // Restart: a fresh process sees the same mailbox.
    server.close();
    server = new TestMailServer(dir, Clock.systemUTC(), FaultInjector.NONE, Duration.ZERO);
    try (MailboxLease lease =
        server.sessions.authenticate(
            "alice@example.org", PASSWORD, CLIENT, Capability.MAIL_ACCESS)) {
      assertThat(inboxSubjects(lease))
          .containsExactly("PRE-ENROLLMENT-MARKER", "WHILE-UNLOCKED-MARKER", "WHILE-LOCKED-MARKER");
      Folder inbox = lease.read(v -> v.folderByRole(SpecialUse.INBOX).orElseThrow());
      assertThat(uids(lease, inbox.folderId())).containsExactly(1L, 2L, 3L);
    }
  }

  @Test
  void bootstrapCredentialAndOldKeyringCannotReadPostEnrollmentMail() throws Exception {
    Path keys = server.paths.keys(alice.mailboxId());
    Path savedKeys = Files.createDirectories(dir.resolve("attacker-copy"));
    try (var files = Files.list(keys)) {
      for (Path f : (Iterable<Path>) files::iterator) {
        Files.copy(f, savedKeys.resolve(f.getFileName()));
      }
    }
    enroll().close();
    deliver("POST-ENROLLMENT-MARKER");

    // The administrator knew the bootstrap password and kept the old key files.
    Argon2idKdf kdf =
        new Argon2idKdf(new KdfAdmission(1 << 20, Duration.ofSeconds(5)), TestMailServer.LIMITS);
    Path oldSlot;
    try (var files = Files.list(savedKeys)) {
      oldSlot =
          files
              .filter(f -> f.getFileName().toString().startsWith("slot-"))
              .findFirst()
              .orElseThrow();
    }
    KeySlot slot = KeySlot.decode(Files.readAllBytes(oldSlot), TestMailServer.LIMITS);
    assertThat(slot.kind()).isEqualTo(SlotKind.BOOTSTRAP);
    try (Secret pw = Secret.utf8(bootstrap);
        SymmetricKey oldMaster = slot.unwrap(pw, kdf);
        Keyring oldKeyring =
            Keyring.open(
                Files.readAllBytes(savedKeys.resolve("keyring")), alice.mailboxId(), oldMaster)) {
      // The old master cannot open the current keyring.
      byte[] currentKeyring = Files.readAllBytes(keys.resolve("keyring"));
      assertThatThrownBy(() -> Keyring.open(currentKeyring, alice.mailboxId(), oldMaster))
          .isInstanceOf(CryptoException.class);
      // And the old private key cannot open receipts sealed after enrollment.
      ReceiptStore.PendingReceipt pending = server.receipts.list(alice.mailboxId()).get(0);
      assertThat(server.receipts.keyVersion(pending)).isEqualTo(2);
      assertThatThrownBy(
              () -> server.receipts.open(alice.mailboxId(), pending, v -> oldKeyring.privateKey(1)))
          .isInstanceOf(org.shem.store.StorageException.class);
    }
  }

  @Test
  void wrongPasswordUnknownUserAndThrottlingAreIndistinguishable() throws Exception {
    enroll().close();
    InetAddress attacker = InetAddress.getByName("192.0.2.7");
    for (String user : List.of("alice@example.org", "nobody@example.org", "not-an-address")) {
      assertThatThrownBy(
              () ->
                  server.sessions.authenticate(
                      user, "wrong password!", attacker, Capability.MAIL_ACCESS))
          .extracting(e -> ((AuthenticationException) e).reason())
          .isEqualTo(AuthenticationException.Reason.INVALID);
    }
    for (int i = 0; i < 3; i++) {
      assertThatThrownBy(
              () ->
                  server.sessions.authenticate(
                      "alice@example.org", "x", attacker, Capability.MAIL_ACCESS))
          .isInstanceOf(AuthenticationException.class);
    }
    assertThatThrownBy(
            () ->
                server.sessions.authenticate(
                    "alice@example.org", PASSWORD, attacker, Capability.MAIL_ACCESS))
        .extracting(e -> ((AuthenticationException) e).reason())
        .isEqualTo(AuthenticationException.Reason.THROTTLED);
    // The legitimate user from another address is not locked out.
    server
        .sessions
        .authenticate("alice@example.org", PASSWORD, CLIENT, Capability.MAIL_ACCESS)
        .close();
  }

  @Test
  void appPasswordsHaveLimitedCapabilitiesAndRevocationEndsTheirSessions() throws Exception {
    try (MailboxLease owner = enroll()) {
      String appPassword;
      try (Secret secret = server.lifecycle.createAppPassword(owner, "phone")) {
        appPassword = new String(secret.exposeCopy(), StandardCharsets.UTF_8);
      }
      MailboxLease phone =
          server.sessions.authenticate(
              "alice@example.org", appPassword, CLIENT, Capability.MAIL_ACCESS);
      assertThat(phone.principal().slotKind()).isEqualTo(SlotKind.APP);
      assertThatThrownBy(
              () -> server.sessions.authenticatePrimary("alice@example.org", appPassword, CLIENT))
          .as("app passwords never open an API session")
          .extracting(e -> ((AuthenticationException) e).reason())
          .isEqualTo(AuthenticationException.Reason.INVALID);
      try (MailboxLease web =
          server.sessions.authenticatePrimary("alice@example.org", PASSWORD, CLIENT)) {
        assertThat(web.principal().can(Capability.KEY_ADMINISTRATION)).isTrue();
      }
      assertThatThrownBy(() -> server.lifecycle.createAppPassword(phone, "nested"))
          .isInstanceOf(SecurityException.class);
      assertThat(server.lifecycle.slots(owner)).extracting(s -> s.label()).contains("phone");

      server.lifecycle.revokeSlot(owner, phone.principal().slotId());
      assertThat(phone.isValid()).isFalse();
      assertThatThrownBy(() -> phone.read(v -> v.folders()))
          .isInstanceOf(RevokedLeaseException.class);
      assertThat(owner.isValid()).isTrue();
      assertThatThrownBy(
              () ->
                  server.sessions.authenticate(
                      "alice@example.org", appPassword, CLIENT, Capability.MAIL_ACCESS))
          .extracting(e -> ((AuthenticationException) e).reason())
          .isEqualTo(AuthenticationException.Reason.INVALID);
      assertThatThrownBy(() -> server.lifecycle.revokeSlot(owner, owner.principal().slotId()))
          .isInstanceOf(KeyLifecycle.LifecycleException.class);
    }
  }

  @Test
  void passwordChangeAndRecoveryCode() throws Exception {
    String recovery;
    try (MailboxLease owner = enroll()) {
      server.lifecycle.changePassword(owner, "a much better passphrase");
      try (Secret code = server.lifecycle.createRecoveryCode(owner)) {
        recovery = new String(code.exposeCopy(), StandardCharsets.UTF_8);
      }
    }
    assertThatThrownBy(
            () ->
                server.sessions.authenticate(
                    "alice@example.org", PASSWORD, CLIENT, Capability.MAIL_ACCESS))
        .isInstanceOf(AuthenticationException.class);
    MailboxLease session =
        server.sessions.authenticate(
            "alice@example.org", "a much better passphrase", CLIENT, Capability.MAIL_ACCESS);
    try (MailboxLease recovering =
        server.sessions.authenticateRecovery("alice@example.org", recovery, CLIENT)) {
      assertThatThrownBy(() -> recovering.read(v -> v.folders()))
          .isInstanceOf(SecurityException.class);
      server.lifecycle.changePassword(recovering, "recovered passphrase!");
    }
    assertThat(session.isValid()).isFalse();
    assertThatThrownBy(
            () -> server.sessions.authenticateRecovery("alice@example.org", recovery, CLIENT))
        .isInstanceOf(AuthenticationException.class);
    server
        .sessions
        .authenticate("alice@example.org", "recovered passphrase!", CLIENT, Capability.MAIL_ACCESS)
        .close();
  }

  @Test
  void receiptReplayIsIdempotentAfterCrashBeforeRetirement() throws Exception {
    enroll().close();
    deliver("REPLAY-MARKER");
    ReceiptStore.PendingReceipt pending = server.receipts.list(alice.mailboxId()).get(0);
    Path saved = dir.resolve("saved-receipt");
    Files.copy(pending.file(), saved);
    try (MailboxLease lease =
        server.sessions.authenticate(
            "alice@example.org", PASSWORD, CLIENT, Capability.MAIL_ACCESS)) {
      assertThat(inboxSubjects(lease)).containsExactly("REPLAY-MARKER");
    }
    // Simulate a crash after the metadata commit but before the receipt file was retired.
    Files.copy(saved, pending.file(), StandardCopyOption.REPLACE_EXISTING);
    try (MailboxLease lease =
        server.sessions.authenticate(
            "alice@example.org", PASSWORD, CLIENT, Capability.MAIL_ACCESS)) {
      assertThat(inboxSubjects(lease)).containsExactly("REPLAY-MARKER");
    }
    assertThat(server.receipts.list(alice.mailboxId())).isEmpty();
  }

  @Test
  void rotationKeepsMailReadableRemovesAppSlotsAndRetiresOldKeys() throws Exception {
    String appPassword;
    try (MailboxLease owner = enroll()) {
      try (Secret secret = server.lifecycle.createAppPassword(owner, "laptop")) {
        appPassword = new String(secret.exposeCopy(), StandardCharsets.UTF_8);
      }
      Folder inbox = owner.read(v -> v.folderByRole(SpecialUse.INBOX).orElseThrow());
      long uid =
          owner.append(
              inbox.folderId(),
              new java.io.ByteArrayInputStream(message("APPENDED")),
              new Flags(Flags.SEEN, List.of()),
              0);
      server.lifecycle.rotateKeys(owner, "rotated passphrase!!");
      assertThat(server.identity.account(alice.mailboxId()).orElseThrow().publicKey().keyVersion())
          .isEqualTo(3);
      assertThat(
              owner.<Boolean>read(
                  v ->
                      v.message(new MessageKey(inbox.folderId(), uid))
                          .orElseThrow()
                          .flags()
                          .has(Flags.SEEN)))
          .isTrue();
      assertThat(inboxSubjects(owner)).containsExactly("APPENDED");
      assertThat(server.lifecycle.slots(owner))
          .extracting(s -> s.kind())
          .containsExactly(SlotKind.PASSWORD);
    }
    assertThatThrownBy(
            () ->
                server.sessions.authenticate(
                    "alice@example.org", appPassword, CLIENT, Capability.MAIL_ACCESS))
        .isInstanceOf(AuthenticationException.class);
    deliver("AFTER-ROTATION");
    try (MailboxLease lease =
        server.sessions.authenticate(
            "alice@example.org", "rotated passphrase!!", CLIENT, Capability.MAIL_ACCESS)) {
      assertThat(inboxSubjects(lease)).containsExactly("APPENDED", "AFTER-ROTATION");
    }
  }

  @Test
  void blockingAnAccountRevokesLiveSessions() throws Exception {
    MailboxLease lease = enroll();
    Account current = server.identity.account(alice.mailboxId()).orElseThrow();
    server.identity.changeState(alice.mailboxId(), current.version(), AccountState.BLOCKED);
    assertThat(lease.isValid()).isFalse();
    assertThat(server.registry.isUnlocked(alice.mailboxId())).isFalse();
    assertThatThrownBy(
            () ->
                server.sessions.authenticate(
                    "alice@example.org", PASSWORD, CLIENT, Capability.MAIL_ACCESS))
        .isInstanceOf(AuthenticationException.class);
  }

  @Test
  void concurrentSessionsShareOneCoordinatorAndLastLogoutLocks() throws Exception {
    MailboxLease first = enroll();
    MailboxLease second =
        server.sessions.authenticate("alice@example.org", PASSWORD, CLIENT, Capability.MAIL_ACCESS);
    assertThat(server.registry.coordinator(alice.mailboxId()).orElseThrow().leaseCount())
        .isEqualTo(2);
    first.close();
    assertThat(server.registry.isUnlocked(alice.mailboxId())).isTrue();
    MailboxLease child = second.child();
    second.close();
    assertThat(child.isValid()).isFalse();
    assertThat(server.registry.isUnlocked(alice.mailboxId())).isFalse();
  }

  /** An extension whose close blocks until released, holding the coordinator in shutdown. */
  private static final class SlowClose implements MailboxExtensionFactory, MailboxExtension {
    final java.util.concurrent.CountDownLatch closing = new java.util.concurrent.CountDownLatch(1);
    final java.util.concurrent.CountDownLatch release = new java.util.concurrent.CountDownLatch(1);

    @Override
    public Class<? extends MailboxExtension> type() {
      return SlowClose.class;
    }

    @Override
    public MailboxExtension open(ExtensionContext context) {
      return this;
    }

    @Override
    public void close() {
      closing.countDown();
      try {
        release.await(10, java.util.concurrent.TimeUnit.SECONDS);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
      }
    }
  }

  @Test
  void loginWhileTheLastSessionIsClosingWaitsForShutdown(@TempDir Path other) throws Exception {
    SlowClose slow = new SlowClose();
    try (TestMailServer slowServer =
        new TestMailServer(
            other, Clock.systemUTC(), FaultInjector.NONE, Duration.ZERO, List.of(slow))) {
      slowServer.identity.createDomain("example.org");
      MailboxProvisioning.Provisioned provisioned =
          slowServer.provisioning.provision(
              EmailAddress.parse("alice@example.org"), 0, Duration.ofDays(1));
      String code;
      try (Secret secret = provisioned.bootstrapPassword()) {
        code = new String(secret.exposeCopy(), StandardCharsets.UTF_8);
      }
      MailboxLease first =
          slowServer.sessions.authenticate("alice@example.org", code, CLIENT, Capability.ENROLL);
      Thread closer = Thread.ofPlatform().start(first::close);
      assertThat(slow.closing.await(10, java.util.concurrent.TimeUnit.SECONDS)).isTrue();
      // The coordinator is closing and its metadata store is still open: a login now must wait.
      Thread releaser =
          Thread.ofPlatform()
              .start(
                  () -> {
                    try {
                      Thread.sleep(300);
                    } catch (InterruptedException e) {
                      Thread.currentThread().interrupt();
                    }
                    slow.release.countDown();
                  });
      try (MailboxLease next =
          slowServer.sessions.authenticate("alice@example.org", code, CLIENT, Capability.ENROLL)) {
        assertThat(next.isValid()).isTrue();
      } finally {
        slow.release.countDown();
        closer.join();
        releaser.join();
      }
    }
  }

  @Test
  void garbageCollectionRemovesOnlyUnreferencedBlobs() throws Exception {
    try (MailboxLease lease = enroll()) {
      Folder inbox = lease.read(v -> v.folderByRole(SpecialUse.INBOX).orElseThrow());
      long keep =
          lease.append(
              inbox.folderId(), new java.io.ByteArrayInputStream(message("KEEP")), Flags.NONE, 0);
      long drop =
          lease.append(
              inbox.folderId(), new java.io.ByteArrayInputStream(message("DROP")), Flags.NONE, 0);
      lease.write(
          tx -> {
            tx.remove(new MessageKey(inbox.folderId(), drop));
            return null;
          });
      assertThat(server.blobs.list(alice.mailboxId())).hasSize(2);
      long freed =
          lease
              .coordinator()
              .collectGarbage(
                  Duration.ZERO, Clock.offset(Clock.systemUTC(), Duration.ofSeconds(5)));
      assertThat(freed).isPositive();
      assertThat(server.blobs.list(alice.mailboxId())).hasSize(1);
      assertThat(uids(lease, inbox.folderId())).containsExactly(keep);
      assertThat(inboxSubjects(lease)).containsExactly("KEEP");
    }
  }

  private static long[] uids(MailboxLease lease, OpaqueId folderId) throws Exception {
    return lease.read(v -> v.uids(folderId));
  }

  private static void awaitInbox(MailboxLease lease, int expected) throws Exception {
    Folder inbox = lease.read(v -> v.folderByRole(SpecialUse.INBOX).orElseThrow());
    java.util.concurrent.CountDownLatch latch = new java.util.concurrent.CountDownLatch(1);
    AutoCloseable subscription = lease.subscribe((txSeq, origin, changes) -> latch.countDown());
    try {
      if (uids(lease, inbox.folderId()).length < expected) {
        latch.await(10, java.util.concurrent.TimeUnit.SECONDS);
      }
    } finally {
      subscription.close();
    }
    assertThat(uids(lease, inbox.folderId())).hasSize(expected);
  }
}
