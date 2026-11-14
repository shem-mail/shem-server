package net.shem.search;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import net.shem.common.FaultInjector;
import net.shem.common.IdGenerator;
import net.shem.common.OpaqueId;
import net.shem.crypto.Argon2Parameters;
import net.shem.crypto.Argon2idKdf;
import net.shem.crypto.KdfAdmission;
import net.shem.crypto.Secret;
import net.shem.delivery.DeliveryRequest;
import net.shem.delivery.DeliveryService;
import net.shem.delivery.MessageSource;
import net.shem.delivery.RecipientDelivery;
import net.shem.identity.DeliveryPolicy;
import net.shem.identity.EmailAddress;
import net.shem.identity.IdentityService;
import net.shem.identity.QuotaLedger;
import net.shem.mailbox.AttemptLimiter;
import net.shem.mailbox.Capability;
import net.shem.mailbox.KeyLifecycle;
import net.shem.mailbox.MailboxLease;
import net.shem.mailbox.MailboxProvisioning;
import net.shem.mailbox.MailboxRegistry;
import net.shem.mailbox.SessionService;
import net.shem.store.BlobStore;
import net.shem.store.DeliveryTarget;
import net.shem.store.MailboxPaths;
import net.shem.store.ReceiptStore;
import net.shem.store.SpecialUse;
import net.shem.store.metadata.MetadataStore;

/** Phase 2 services with the search index registered as a mailbox extension. */
final class SearchFixture implements AutoCloseable {
  static final SecureRandom RANDOM = new SecureRandom();
  static final String USER = "alice@example.org";
  static final String PASSWORD = "correct horse battery staple";

  final MailboxPaths paths;
  final IdentityService identity;
  final MailboxRegistry registry;
  final SessionService sessions;
  final KeyLifecycle lifecycle;
  final DeliveryService delivery;
  final OpaqueId mailboxId;
  private final ExecutorService background = Executors.newFixedThreadPool(2);
  private final ExecutorService indexing = Executors.newFixedThreadPool(1);

  SearchFixture(Path root) throws Exception {
    this(root, List.of(new SearchIndexFactory()));
  }

  SearchFixture(Path root, List<net.shem.mailbox.MailboxExtensionFactory> extensions)
      throws Exception {
    Clock clock = Clock.systemUTC();
    IdGenerator ids = IdGenerator.secure(RANDOM);
    paths = new MailboxPaths(root.resolve("mailboxes"));
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
                paths, blobs, receipts, quota, identity, env, 10 << 20, extensions, indexing),
            background);
    lifecycle = new KeyLifecycle(identity, registry, kdf, cheap, ids, RANDOM, clock, Duration.ZERO);
    sessions =
        new SessionService(
            identity,
            kdf,
            cheap,
            new AttemptLimiter(clock, AttemptLimiter.Policy.DEFAULT),
            registry,
            lifecycle,
            RANDOM);
    delivery = new DeliveryService(blobs, receipts, quota, registry, 10 << 20);
    identity.createDomain("example.org");
    MailboxProvisioning.Provisioned provisioned =
        new MailboxProvisioning(identity, paths, kdf, cheap, env, ids, RANDOM, clock)
            .provision(EmailAddress.parse(USER), 0, Duration.ofDays(1));
    mailboxId = provisioned.account().mailboxId();
    String bootstrap;
    try (Secret secret = provisioned.bootstrapPassword()) {
      bootstrap = new String(secret.exposeCopy(), StandardCharsets.UTF_8);
    }
    try (MailboxLease lease =
        sessions.authenticate(
            USER, bootstrap, java.net.InetAddress.getLoopbackAddress(), Capability.ENROLL)) {
      lifecycle.enroll(lease, PASSWORD);
    }
  }

  MailboxLease login() throws Exception {
    return sessions.authenticate(
        USER, PASSWORD, java.net.InetAddress.getLoopbackAddress(), Capability.MAIL_ACCESS);
  }

  void deliver(byte[] message) throws Exception {
    delivery.deliver(
        new DeliveryRequest(
            OpaqueId.random(RANDOM),
            List.of(
                new RecipientDelivery(
                    identity.resolveRecipient(EmailAddress.parse(USER)).get(0),
                    USER,
                    new DeliveryTarget.Role(SpecialUse.INBOX),
                    0,
                    List.of(),
                    List.of())),
            MessageSource.ofBytes(message),
            System.currentTimeMillis(),
            "bob@example.net"));
  }

  @Override
  public void close() {
    registry.close();
    background.shutdownNow();
    indexing.shutdownNow();
  }
}
