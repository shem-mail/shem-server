package org.shem.mailbox;

import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.shem.common.FaultInjector;
import org.shem.common.IdGenerator;
import org.shem.crypto.Argon2Parameters;
import org.shem.crypto.Argon2idKdf;
import org.shem.crypto.KdfAdmission;
import org.shem.delivery.DeliveryService;
import org.shem.identity.DeliveryPolicy;
import org.shem.identity.IdentityService;
import org.shem.identity.QuotaLedger;
import org.shem.store.BlobStore;
import org.shem.store.MailboxPaths;
import org.shem.store.ReceiptStore;
import org.shem.store.metadata.MetadataStore;

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
                paths, blobs, receipts, quota, identity, env, 10 << 20),
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
