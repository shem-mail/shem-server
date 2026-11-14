package net.shem.mailbox;

import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import net.shem.common.FaultInjector;
import net.shem.common.IdGenerator;
import net.shem.crypto.Argon2Parameters;
import net.shem.crypto.Argon2idKdf;
import net.shem.crypto.KdfAdmission;
import net.shem.delivery.DeliveryService;
import net.shem.identity.DeliveryPolicy;
import net.shem.identity.IdentityService;
import net.shem.identity.QuotaLedger;
import net.shem.store.BlobStore;
import net.shem.store.MailboxPaths;
import net.shem.store.ReceiptStore;
import net.shem.store.metadata.MetadataStore;

/** Wires the Phase 2 services over a directory, like the runtime composition root does. */
final class TestMailServer implements AutoCloseable {
  static final SecureRandom RANDOM = new SecureRandom();
  static final Argon2Parameters.Limits LIMITS = new Argon2Parameters.Limits(8, 1 << 20, 10, 8);
  static final Argon2Parameters CHEAP = new Argon2Parameters(64, 1, 1);

  final Path root;
  final MailboxPaths paths;
  final IdentityService identity;
  final BlobStore blobs;
  final ReceiptStore receipts;
  final QuotaLedger quota;
  final MailboxRegistry registry;
  final KeyLifecycle lifecycle;
  final SessionService sessions;
  final MailboxProvisioning provisioning;
  final DeliveryService delivery;
  final AttemptLimiter limiter;
  private final ExecutorService background = Executors.newFixedThreadPool(2);

  TestMailServer(Path root, Clock clock, FaultInjector faults, Duration oldKeyRetention)
      throws Exception {
    this(root, clock, faults, oldKeyRetention, java.util.List.of());
  }

  TestMailServer(
      Path root,
      Clock clock,
      FaultInjector faults,
      Duration oldKeyRetention,
      java.util.List<MailboxExtensionFactory> extensions)
      throws Exception {
    this.root = root;
    IdGenerator ids = IdGenerator.secure(RANDOM);
    paths = new MailboxPaths(root.resolve("mailboxes"));
    identity =
        IdentityService.open(
            root.resolve("routing/directory.bin"),
            clock,
            ids,
            DeliveryPolicy.DEFAULT,
            Duration.ofDays(30));
    blobs = new BlobStore(paths, ids, RANDOM, faults);
    receipts = new ReceiptStore(paths, ids, RANDOM, clock, faults);
    quota = new QuotaLedger(paths::mailbox);
    Argon2idKdf kdf = new Argon2idKdf(new KdfAdmission(1 << 20, Duration.ofSeconds(5)), LIMITS);
    MetadataStore.Environment env =
        new MetadataStore.Environment(ids, RANDOM, clock, faults, MetadataStore.Options.DEFAULT);
    registry =
        new MailboxRegistry(
            new MailboxRegistry.Dependencies(
                paths, blobs, receipts, quota, identity, env, 10 << 20, extensions, background),
            background);
    lifecycle =
        new KeyLifecycle(identity, registry, kdf, CHEAP, ids, RANDOM, clock, oldKeyRetention);
    limiter = new AttemptLimiter(clock, AttemptLimiter.Policy.DEFAULT);
    sessions = new SessionService(identity, kdf, CHEAP, limiter, registry, lifecycle, RANDOM);
    provisioning = new MailboxProvisioning(identity, paths, kdf, CHEAP, env, ids, RANDOM, clock);
    delivery = new DeliveryService(blobs, receipts, quota, registry, 10 << 20);
  }

  @Override
  public void close() {
    registry.close();
    background.shutdownNow();
  }
}
