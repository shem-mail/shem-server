package org.shem.search;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
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
                paths,
                blobs,
                receipts,
                quota,
                identity,
                env,
                10 << 20,
                List.of(new SearchIndexFactory()),
                indexing),
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
