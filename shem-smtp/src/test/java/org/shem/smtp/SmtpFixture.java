package org.shem.smtp;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.jspecify.annotations.Nullable;
import org.shem.common.FaultInjector;
import org.shem.common.IdGenerator;
import org.shem.crypto.Argon2Parameters;
import org.shem.crypto.Argon2idKdf;
import org.shem.crypto.KdfAdmission;
import org.shem.crypto.Secret;
import org.shem.delivery.DeliveryService;
import org.shem.identity.DeliveryPolicy;
import org.shem.identity.EmailAddress;
import org.shem.identity.IdentityService;
import org.shem.identity.QuotaLedger;
import org.shem.mailbox.AttemptLimiter;
import org.shem.mailbox.Capability;
import org.shem.mailbox.KeyLifecycle;
import org.shem.mailbox.MailboxLease;
import org.shem.mailbox.MailboxProvisioning;
import org.shem.mailbox.MailboxRegistry;
import org.shem.mailbox.SessionService;
import org.shem.policy.Greylist;
import org.shem.policy.InboundPolicy;
import org.shem.store.BlobStore;
import org.shem.store.MailboxPaths;
import org.shem.store.ReceiptStore;
import org.shem.store.SpecialUse;
import org.shem.store.metadata.Folder;
import org.shem.store.metadata.MessageRecord;
import org.shem.store.metadata.MetadataStore;
import org.shem.tls.ReloadableTlsContext;
import org.shem.tls.TestCertificates;

/** Real inbound SMTP listener over the Phase 2 services; alice is enrolled, carol is not. */
final class SmtpFixture implements AutoCloseable {
  static final SecureRandom RANDOM = new SecureRandom();
  static final String HOST = "localhost";
  static final String ALICE = "alice@example.org";
  static final String CAROL = "carol@example.org";
  static final String PASSWORD = "correct horse battery staple";
  static final long MAX_MESSAGE = 512 * 1024;
  static final int MEMORY_THRESHOLD = 64 * 1024;

  final Path root;
  final Path spool;
  final IdentityService identity;
  final MailboxRegistry registry;
  final SessionService sessions;
  final TestCertificates.Files2 certificate;
  final InboundSmtpRole smtp;
  final int port;

  /** DNS answers for policy, keyed by {@code name/TYPE}; unlisted names do not exist. */
  final Map<String, List<String>> dns = new ConcurrentHashMap<>();

  /** Set to make the next blob writes fail as if the disk were full. */
  volatile boolean diskFull;

  private final ExecutorService background = Executors.newFixedThreadPool(2);

  SmtpFixture(Path root) throws Exception {
    this(root, null);
  }

  SmtpFixture(Path root, Greylist.@Nullable Settings greylisting) throws Exception {
    this.root = root;
    this.spool = root.resolve("spool");
    Clock clock = Clock.systemUTC();
    IdGenerator ids = IdGenerator.secure(RANDOM);
    MailboxPaths paths = new MailboxPaths(root.resolve("mailboxes"));
    identity =
        IdentityService.open(
            root.resolve("routing/directory.bin"),
            clock,
            ids,
            DeliveryPolicy.DEFAULT,
            Duration.ofDays(30));
    FaultInjector faults =
        point -> {
          if (diskFull) {
            throw new IOException("No space left on device");
          }
        };
    BlobStore blobs = new BlobStore(paths, ids, RANDOM, faults);
    ReceiptStore receipts = new ReceiptStore(paths, ids, RANDOM, clock, FaultInjector.NONE);
    QuotaLedger quota = new QuotaLedger(paths::mailbox);
    Argon2Parameters cheap = new Argon2Parameters(64, 1, 1);
    Argon2idKdf kdf =
        new Argon2idKdf(
            new KdfAdmission(1 << 20, Duration.ofSeconds(5)),
            new Argon2Parameters.Limits(8, 1 << 20, 10, 8));
    MetadataStore.Environment env =
        new MetadataStore.Environment(
            ids, RANDOM, clock, FaultInjector.NONE, MetadataStore.Options.DEFAULT);
    registry =
        new MailboxRegistry(
            new MailboxRegistry.Dependencies(
                paths, blobs, receipts, quota, identity, env, 10 << 20),
            background);
    KeyLifecycle lifecycle =
        new KeyLifecycle(identity, registry, kdf, cheap, ids, RANDOM, clock, Duration.ZERO);
    sessions =
        new SessionService(
            identity,
            kdf,
            cheap,
            new AttemptLimiter(clock, AttemptLimiter.Policy.DEFAULT),
            registry,
            lifecycle,
            RANDOM);
    MailboxProvisioning provisioning =
        new MailboxProvisioning(identity, paths, kdf, cheap, env, ids, RANDOM, clock);
    DeliveryService delivery = new DeliveryService(blobs, receipts, quota, registry, 10 << 20);

    identity.createDomain("example.org");
    MailboxProvisioning.Provisioned alice =
        provisioning.provision(EmailAddress.parse(ALICE), 0, Duration.ofDays(1));
    String bootstrap;
    try (Secret secret = alice.bootstrapPassword()) {
      bootstrap = new String(secret.exposeCopy(), StandardCharsets.UTF_8);
    }
    try (MailboxLease lease =
        sessions.authenticate(
            ALICE, bootstrap, InetAddress.getLoopbackAddress(), Capability.ENROLL)) {
      lifecycle.enroll(lease, PASSWORD);
    }
    provisioning
        .provision(EmailAddress.parse(CAROL), 0, Duration.ofDays(1))
        .bootstrapPassword()
        .close();
    identity.createAlias(
        EmailAddress.parse("team@example.org"),
        List.of(EmailAddress.parse(ALICE), EmailAddress.parse(CAROL)),
        List.of());

    certificate =
        TestCertificates.write(
            root.resolve("tls"), HOST, Instant.now().minusSeconds(60), Duration.ofDays(30));
    ReloadableTlsContext tls =
        ReloadableTlsContext.open(certificate.chain(), certificate.key(), List.of(HOST), clock);
    try (ServerSocket probe = new ServerSocket(0)) {
      port = probe.getLocalPort();
    }
    smtp =
        InboundSmtpRole.start(
            new InboundSettings(
                new InetSocketAddress(InetAddress.getLoopbackAddress(), port),
                HOST,
                20,
                10,
                300,
                MAX_MESSAGE,
                MEMORY_THRESHOLD,
                5,
                3,
                spool),
            identity,
            delivery,
            new InboundPolicy(
                new InboundPolicy.Settings(
                    HOST,
                    5.0,
                    InboundPolicy.Enforcement.REJECT,
                    InboundPolicy.Enforcement.REJECT,
                    List.of()),
                (name, type) -> dns.getOrDefault(name + "/" + type, List.of()),
                RANDOM),
            greylisting == null ? null : new Greylist(greylisting, clock, RANDOM),
            tls,
            ids,
            RANDOM,
            clock);
  }

  SmtpClient connect() throws Exception {
    return new SmtpClient(port, TestCertificates.clientTrusting(certificate.certificate()));
  }

  /** Unlocks alice, imports pending receipts, and returns her INBOX messages in UID order. */
  List<byte[]> aliceInbox() throws Exception {
    return aliceFolder(SpecialUse.INBOX);
  }

  /** Alice's messages in the folder with {@code role}; empty if it does not exist. */
  List<byte[]> aliceFolder(SpecialUse role) throws Exception {
    try (MailboxLease lease =
        sessions.authenticate(
            ALICE, PASSWORD, InetAddress.getLoopbackAddress(), Capability.MAIL_ACCESS)) {
      lease.importPending(1000);
      java.util.Optional<Folder> folder = lease.read(v -> v.folderByRole(role));
      if (folder.isEmpty()) {
        return List.of();
      }
      Folder inbox = folder.get();
      List<MessageRecord> records = new ArrayList<>();
      lease.read(
          v -> {
            v.forEachMessage(inbox.folderId(), (uid, r) -> records.add(r));
            return null;
          });
      List<byte[]> messages = new ArrayList<>();
      for (MessageRecord r : records) {
        try (var in = lease.openMessage(r)) {
          messages.add(in.readAllBytes());
        }
      }
      return messages;
    }
  }

  @Override
  public void close() {
    smtp.close();
    registry.close();
    background.shutdownNow();
  }
}
