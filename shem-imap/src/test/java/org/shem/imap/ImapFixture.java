package org.shem.imap;

import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.shem.common.FaultInjector;
import org.shem.common.IdGenerator;
import org.shem.common.OpaqueId;
import org.shem.crypto.Argon2Parameters;
import org.shem.crypto.Argon2idKdf;
import org.shem.crypto.KdfAdmission;
import org.shem.crypto.Secret;
import org.shem.delivery.DeliveryRequest;
import org.shem.delivery.DeliveryService;
import org.shem.delivery.MessageSource;
import org.shem.delivery.RecipientDelivery;
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
import org.shem.store.BlobStore;
import org.shem.store.DeliveryTarget;
import org.shem.store.MailboxPaths;
import org.shem.store.ReceiptStore;
import org.shem.store.SpecialUse;
import org.shem.store.metadata.MetadataStore;
import org.shem.tls.ReloadableTlsContext;
import org.shem.tls.TestCertificates;

/** Real IMAP listener over TLS with the Phase 2 services, for client interoperability tests. */
final class ImapFixture implements AutoCloseable {
  static final SecureRandom RANDOM = new SecureRandom();
  static final String HOST = "localhost";
  static final String USER = "alice@example.org";
  static final String PASSWORD = "correct horse battery staple";

  final Path root;
  final IdentityService identity;
  final MailboxRegistry registry;
  final DeliveryService delivery;
  final SessionService sessions;
  final TestCertificates.Files2 certificate;
  final ImapRole imap;
  final int port;
  private final ExecutorService background = Executors.newFixedThreadPool(2);
  final ExecutorService indexing = Executors.newSingleThreadExecutor();

  ImapFixture(Path root) throws Exception {
    this.root = root;
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
    BlobStore blobs = new BlobStore(paths, ids, RANDOM, FaultInjector.NONE);
    ReceiptStore receipts = new ReceiptStore(paths, ids, RANDOM, clock, FaultInjector.NONE);
    QuotaLedger quota = new QuotaLedger(paths::mailbox);
    Argon2Parameters.Limits limits = new Argon2Parameters.Limits(8, 1 << 20, 10, 8);
    Argon2Parameters cheap = new Argon2Parameters(64, 1, 1);
    Argon2idKdf kdf = new Argon2idKdf(new KdfAdmission(1 << 20, Duration.ofSeconds(5)), limits);
    MetadataStore.Environment env =
        new MetadataStore.Environment(
            ids, RANDOM, clock, FaultInjector.NONE, MetadataStore.Options.DEFAULT);
    registry =
        new MailboxRegistry(
            new MailboxRegistry.Dependencies(
                paths,
                blobs,
                receipts,
                quota,
                identity,
                env,
                10 << 20,
                List.of(new org.shem.search.SearchIndexFactory()),
                indexing),
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
    delivery = new DeliveryService(blobs, receipts, quota, registry, 10 << 20);

    identity.createDomain("example.org");
    MailboxProvisioning.Provisioned provisioned =
        provisioning.provision(EmailAddress.parse(USER), 0, Duration.ofDays(1));
    String bootstrap;
    try (Secret secret = provisioned.bootstrapPassword()) {
      bootstrap = new String(secret.exposeCopy(), StandardCharsets.UTF_8);
    }
    try (MailboxLease lease =
        sessions.authenticate(
            USER, bootstrap, java.net.InetAddress.getLoopbackAddress(), Capability.ENROLL)) {
      lifecycle.enroll(lease, PASSWORD);
    }

    certificate =
        TestCertificates.write(
            root.resolve("tls"), HOST, Instant.now().minusSeconds(60), Duration.ofDays(30));
    ReloadableTlsContext tls =
        ReloadableTlsContext.open(certificate.chain(), certificate.key(), List.of(HOST), clock);
    try (ServerSocket probe = new ServerSocket(0)) {
      port = probe.getLocalPort();
    }
    imap =
        ImapRole.start(
            new ImapRole.Settings(
                new InetSocketAddress(java.net.InetAddress.getLoopbackAddress(), port),
                HOST,
                50,
                20,
                10 << 20,
                1800),
            sessions,
            tls);
  }

  void deliverRaw(byte[] message) {
    delivery.deliver(
        new DeliveryRequest(
            OpaqueId.random(RANDOM),
            List.of(
                new RecipientDelivery(
                    route(),
                    USER,
                    new DeliveryTarget.Role(SpecialUse.INBOX),
                    0,
                    List.of(),
                    List.of())),
            MessageSource.ofBytes(message),
            System.currentTimeMillis(),
            "bob@example.net"));
  }

  void deliver(String subject, String body) {
    var routes = route();
    delivery.deliver(
        new DeliveryRequest(
            OpaqueId.random(RANDOM),
            List.of(
                new RecipientDelivery(
                    routes,
                    USER,
                    new DeliveryTarget.Role(SpecialUse.INBOX),
                    0,
                    List.of(),
                    List.of())),
            MessageSource.ofBytes(
                ("From: Bob <bob@example.net>\r\nTo: "
                        + USER
                        + "\r\nSubject: "
                        + subject
                        + "\r\nDate: Sun, 25 Oct 2026 10:00:00 +0000\r\nMessage-ID: <"
                        + subject.hashCode()
                        + "@example.net>\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
                        + body
                        + "\r\n")
                    .getBytes(StandardCharsets.UTF_8)),
            System.currentTimeMillis(),
            "bob@example.net"));
  }

  private org.shem.identity.RecipientRoute route() {
    try {
      return identity.resolveRecipient(EmailAddress.parse(USER)).get(0);
    } catch (org.shem.identity.IdentityException e) {
      throw new IllegalStateException(e);
    }
  }

  @Override
  public void close() {
    imap.close();
    registry.close();
    background.shutdownNow();
    indexing.shutdownNow();
  }
}
