package org.shem.app;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.shem.common.OpaqueId;
import org.shem.crypto.Secret;
import org.shem.delivery.DeliveryRequest;
import org.shem.delivery.MessageSource;
import org.shem.delivery.RecipientDelivery;
import org.shem.identity.EmailAddress;
import org.shem.mailbox.Capability;
import org.shem.mailbox.MailboxLease;
import org.shem.mailbox.MailboxProvisioning;
import org.shem.search.SearchIndex;
import org.shem.store.DeliveryTarget;
import org.shem.store.SpecialUse;
import org.shem.store.metadata.Flags;
import org.shem.store.metadata.Folder;

/** Restore drill (ADR 0020): back up, restore to a fresh directory, sign in, read everything. */
class BackupRestoreTest {
  private static final String ALICE = "alice@example.org";
  private static final String PASSWORD = "correct horse battery staple";
  private static final InetAddress CLIENT = InetAddress.getLoopbackAddress();
  @TempDir Path dir;

  private ShemConfig config(Path data) {
    Properties p = new Properties();
    p.setProperty("data.directory", data.toString());
    p.setProperty("mode", "development");
    p.setProperty("argon2.memoryKiB", String.valueOf(19 * 1024));
    p.setProperty("argon2.iterations", "1");
    return ShemConfig.fromProperties(p, dir);
  }

  private static byte[] message(String marker) {
    return ("From: bob@example.net\r\nSubject: " + marker + "\r\n\r\nbody " + marker + "\r\n")
        .getBytes(StandardCharsets.US_ASCII);
  }

  /** Alice with one appended message and one delivered while locked (a pending receipt). */
  private void populate(Path data) throws Exception {
    try (Services services = Services.start(config(data))) {
      services.identity.createDomain("example.org");
      MailboxProvisioning.Provisioned provisioned =
          services.provisioning.provision(EmailAddress.parse(ALICE), 0, Duration.ofDays(1));
      String bootstrap;
      try (Secret secret = provisioned.bootstrapPassword()) {
        bootstrap = new String(secret.exposeCopy(), StandardCharsets.UTF_8);
      }
      try (MailboxLease lease =
          services.sessions.authenticate(ALICE, bootstrap, CLIENT, Capability.ENROLL)) {
        services.lifecycle.enroll(lease, PASSWORD);
      }
      try (MailboxLease lease =
          services.sessions.authenticate(ALICE, PASSWORD, CLIENT, Capability.MAIL_ACCESS)) {
        Folder inbox = lease.read(v -> v.folderByRole(SpecialUse.INBOX).orElseThrow());
        lease.append(
            inbox.folderId(), new ByteArrayInputStream(message("APPENDED-MARK")), Flags.NONE, 0);
        lease.extension(SearchIndex.class).orElseThrow().awaitIdle(Duration.ofSeconds(30));
      }
      services.registry.revokeMailbox(provisioned.account().mailboxId());
      services.delivery.deliver(
          new DeliveryRequest(
              OpaqueId.random(services.random),
              List.of(
                  new RecipientDelivery(
                      services.identity.resolveRecipient(EmailAddress.parse(ALICE)).get(0),
                      ALICE,
                      new DeliveryTarget.Role(SpecialUse.INBOX),
                      0,
                      List.of(),
                      List.of())),
              MessageSource.ofBytes(message("LOCKED-MARK")),
              System.currentTimeMillis(),
              "bob@example.net"));
      services.admins.create("ops", "an administrator passphrase").close();
    }
  }

  private static List<String> subjects(Services services) throws Exception {
    try (MailboxLease lease =
        services.sessions.authenticate(ALICE, PASSWORD, CLIENT, Capability.MAIL_ACCESS)) {
      Folder inbox = lease.read(v -> v.folderByRole(SpecialUse.INBOX).orElseThrow());
      List<String> out = new ArrayList<>();
      for (long uid : lease.read(v -> v.uids(inbox.folderId()))) {
        var record =
            lease
                .read(v -> v.message(new org.shem.store.metadata.MessageKey(inbox.folderId(), uid)))
                .orElseThrow();
        try (InputStream in = lease.openMessage(record)) {
          String text = new String(in.readAllBytes(), StandardCharsets.US_ASCII);
          out.add(text.substring(text.indexOf("Subject: ") + 9, text.indexOf("\r\n\r\n")));
        }
      }
      SearchIndex index = lease.extension(SearchIndex.class).orElseThrow();
      assertThat(index.awaitIdle(Duration.ofSeconds(30))).isTrue();
      SearchIndex.Snapshot snapshot = index.acquire();
      try {
        assertThat(snapshot.coveredCount()).as("index rebuilt after restore").isEqualTo(out.size());
      } finally {
        index.release(snapshot);
      }
      return out;
    }
  }

  @Test
  void aRestoredDataDirectoryServesTheSameMailWithTheUsersOwnCredentials() throws Exception {
    Path data = dir.resolve("data");
    populate(data);
    Path backup = dir.resolve("backup");
    try (DataDirectory locked = DataDirectory.open(data)) {
      List<Backup.Entry> entries =
          Backup.create(locked.root(), backup, new Backup.Scope(false, true), Instant.EPOCH);
      assertThat(entries)
          .extracting(Backup.Entry::path)
          .noneMatch(
              p -> p.contains("searchindex") || p.startsWith("spool") || p.equals("shem.lock"))
          .anyMatch(p -> p.startsWith("admin/"))
          .anyMatch(p -> p.startsWith("routing/"));
    }
    assertThat(Backup.verify(backup)).isNotEmpty();
    org.shem.store.PlaintextScan.assertNoMarkers(backup, "APPENDED-MARK", "LOCKED-MARK");

    Path restored = dir.resolve("restored");
    Backup.restore(backup, restored);
    try (Services services = Services.start(config(restored))) {
      assertThat(subjects(services))
          .as("appended mail and the pending locked delivery both survive")
          .containsExactlyInAnyOrder("APPENDED-MARK", "LOCKED-MARK");
      assertThat(services.admins.names()).containsExactly("ops");
      assertThatThrownBy(
              () ->
                  services.sessions.authenticate(
                      ALICE, "a wrong password entirely", CLIENT, Capability.MAIL_ACCESS))
          .as("no password recovery through restore")
          .isInstanceOf(org.shem.mailbox.AuthenticationException.class);
    }
  }

  private Path freshBackup(String name, Backup.Scope scope) throws Exception {
    Path data = dir.resolve(name + "-data");
    populate(data);
    Path backup = dir.resolve(name);
    try (DataDirectory locked = DataDirectory.open(data)) {
      Backup.create(locked.root(), backup, scope, Instant.EPOCH);
    }
    return backup;
  }

  private static Path someBlob(Path backup) throws Exception {
    try (Stream<Path> files = Files.walk(backup.resolve("mailboxes"))) {
      return files
          .filter(Files::isRegularFile)
          .filter(p -> p.toString().contains("blobs"))
          .findFirst()
          .orElseThrow();
    }
  }

  @Test
  void damagedBackupsAreDetectedAndNeverRestored() throws Exception {
    Path backup = freshBackup("b1", new Backup.Scope(false, true));
    Path blob = someBlob(backup);
    byte[] original = Files.readAllBytes(blob);

    byte[] flipped = original.clone();
    flipped[flipped.length / 2] ^= 1;
    Files.write(blob, flipped);
    assertThatThrownBy(() -> Backup.verify(backup)).hasMessageContaining("altered file");
    Path target = dir.resolve("target");
    assertThatThrownBy(() -> Backup.restore(backup, target))
        .isInstanceOf(Backup.InvalidBackupException.class);
    assertThat(target).as("nothing restored").doesNotExist();

    Files.delete(blob);
    assertThatThrownBy(() -> Backup.verify(backup)).hasMessageContaining("missing file");
    Files.write(blob, original);
    Files.writeString(backup.resolve("routing/extra.bin"), "x");
    assertThatThrownBy(() -> Backup.verify(backup)).hasMessageContaining("unlisted file");
    Files.delete(backup.resolve("routing/extra.bin"));

    Path manifest = backup.resolve(Backup.MANIFEST);
    String text = Files.readString(manifest);
    Files.writeString(manifest, text.replace("queue false", "queue true"));
    assertThatThrownBy(() -> Backup.verify(backup)).hasMessageContaining("manifest was modified");
    Files.delete(manifest);
    assertThatThrownBy(() -> Backup.verify(backup)).hasMessageContaining("incomplete");
  }

  @Test
  void restoreNeedsAnEmptyTargetAndRecoversFromAnInterruptedRestore() throws Exception {
    Path backup = freshBackup("b2", new Backup.Scope(false, false));
    assertThat(Backup.verify(backup))
        .extracting(Backup.Entry::path)
        .as("secrets excluded on request")
        .noneMatch(p -> p.startsWith("admin/") || p.startsWith("dkim/") || p.startsWith("acme/"));
    Path occupied = dir.resolve("occupied");
    Files.createDirectories(occupied);
    Files.writeString(occupied.resolve("file"), "x");
    assertThatThrownBy(() -> Backup.restore(backup, occupied)).hasMessageContaining("not empty");

    Path target = dir.resolve("target");
    Path staging = dir.resolve("target.restore-staging");
    Files.createDirectories(staging.resolve("mailboxes"));
    Files.writeString(staging.resolve("mailboxes/partial"), "left by a crash");
    Backup.restore(backup, target);
    assertThat(staging).doesNotExist();
    assertThat(target.resolve("mailboxes/partial")).doesNotExist();
    try (Services services = Services.start(config(target))) {
      assertThat(subjects(services)).hasSize(2);
    }
  }
}
