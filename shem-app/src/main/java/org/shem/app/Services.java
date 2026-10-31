package org.shem.app;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import org.jspecify.annotations.Nullable;
import org.shem.common.FaultInjector;
import org.shem.common.FormatException;
import org.shem.common.IdGenerator;
import org.shem.crypto.Argon2Parameters;
import org.shem.crypto.Argon2idKdf;
import org.shem.crypto.KdfAdmission;
import org.shem.delivery.DeliveryService;
import org.shem.extract.ExtractionSettings;
import org.shem.extract.WorkerPool;
import org.shem.identity.AdminStore;
import org.shem.identity.AuditLog;
import org.shem.identity.DeliveryPolicy;
import org.shem.identity.IdentityService;
import org.shem.identity.QuotaLedger;
import org.shem.mailbox.AttemptLimiter;
import org.shem.mailbox.KeyLifecycle;
import org.shem.mailbox.MailboxExtensionFactory;
import org.shem.mailbox.MailboxProvisioning;
import org.shem.mailbox.MailboxRegistry;
import org.shem.mailbox.SessionService;
import org.shem.search.AttachmentIndexFactory;
import org.shem.search.SearchIndexFactory;
import org.shem.smtp.InboundSmtpRole;
import org.shem.store.BlobStore;
import org.shem.store.MailboxPaths;
import org.shem.store.ReceiptStore;
import org.shem.store.metadata.MetadataStore;

/**
 * Composition root: constructs every service with explicit constructor injection. No service
 * locator or static state; protocol roles receive only the services they need.
 */
public final class Services implements AutoCloseable {
  public final ShemConfig config;
  public final DataDirectory data;
  public final IdentityService identity;
  public final MailboxPaths paths;
  public final DeliveryService delivery;
  public final MailboxRegistry registry;
  public final KeyLifecycle lifecycle;
  public final SessionService sessions;
  public final MailboxProvisioning provisioning;

  /** Attachment extraction workers (ADR 0019); started by {@code serve}, absent if disabled. */
  public final @Nullable WorkerPool extraction;

  public final AdminStore admins;
  public final AuditLog audit;
  public final IdGenerator ids;
  public final SecureRandom random;
  public final Clock clock;
  private final ExecutorService background;
  private final ExecutorService indexing;

  private Services(ShemConfig config, DataDirectory data, Clock clock, SecureRandom random)
      throws IOException, FormatException {
    this.config = config;
    this.data = data;
    this.random = random;
    this.clock = clock;
    this.ids = IdGenerator.secure(random);
    ShemConfig.Extraction extractionConfig = config.extraction();
    this.extraction =
        extractionConfig == null
            ? null
            : new WorkerPool(
                new ExtractionSettings(
                    extractionConfig.sandbox() == null
                        ? List.of()
                        : List.of(extractionConfig.sandbox().toString()),
                    extractionConfig.scratch(),
                    data.root().resolve(".extraction-canary"),
                    extractionConfig.workers(),
                    extractionConfig.timeout(),
                    extractionConfig.maxInputBytes(),
                    extractionConfig.maxOutputChars(),
                    extractionConfig.heapMiB(),
                    extractionConfig.requestsPerWorker(),
                    extractionConfig.requireIsolation()));
    this.identity =
        IdentityService.open(
            data.routingFile(),
            clock,
            ids,
            new DeliveryPolicy(config.acceptMailBeforeEnrollment(), false),
            config.recreationWaitingPeriod());
    this.paths = new MailboxPaths(data.mailboxes());
    BlobStore blobs = new BlobStore(paths, ids, random, FaultInjector.NONE);
    ReceiptStore receipts = new ReceiptStore(paths, ids, random, clock, FaultInjector.NONE);
    QuotaLedger quota = new QuotaLedger(paths::mailbox);
    Argon2idKdf kdf =
        new Argon2idKdf(
            new KdfAdmission(config.kdfBudgetKiB(), config.kdfMaxWait()),
            Argon2Parameters.Limits.DEFAULT);
    MetadataStore.Environment metadataEnvironment =
        new MetadataStore.Environment(
            ids, random, clock, FaultInjector.NONE, MetadataStore.Options.DEFAULT);
    this.background =
        new ThreadPoolExecutor(
            1,
            4,
            30,
            TimeUnit.SECONDS,
            new ArrayBlockingQueue<>(1024),
            Thread.ofVirtual().factory());
    // Indexing is CPU-bound: a small platform pool, one queued drain task per unlocked mailbox.
    // A rejected drain only delays coverage; SEARCH evaluates uncovered messages exactly.
    this.indexing =
        new ThreadPoolExecutor(
            1,
            2,
            30,
            TimeUnit.SECONDS,
            new ArrayBlockingQueue<>(1024),
            Thread.ofPlatform().name("shem-index-", 0).daemon(true).factory());
    this.registry =
        new MailboxRegistry(
            new MailboxRegistry.Dependencies(
                paths,
                blobs,
                receipts,
                quota,
                identity,
                metadataEnvironment,
                config.maxMessageBytes(),
                extensions(),
                indexing),
            background);
    this.lifecycle =
        new KeyLifecycle(
            identity,
            registry,
            kdf,
            config.slotParameters(),
            ids,
            random,
            clock,
            config.oldKeyRetention());
    this.sessions =
        new SessionService(
            identity,
            kdf,
            config.slotParameters(),
            new AttemptLimiter(clock, AttemptLimiter.Policy.DEFAULT),
            registry,
            lifecycle,
            random);
    this.provisioning =
        new MailboxProvisioning(
            identity, paths, kdf, config.slotParameters(), metadataEnvironment, ids, random, clock);
    try {
      this.audit =
          AuditLog.open(
              data.root().resolve("audit").resolve("audit.log"),
              clock,
              config.auditToStdout() ? System.out : null);
    } catch (AuditLog.BrokenChainException e) {
      throw new IOException("audit log failed verification: " + e.getMessage(), e);
    }
    this.admins =
        AdminStore.open(data.adminFile(), kdf, config.slotParameters(), ids, random, clock);
    // Inbound SMTP prepends trace and policy fields to messages of up to message.maxBytes.
    this.delivery =
        new DeliveryService(
            blobs,
            receipts,
            quota,
            registry,
            config.maxMessageBytes() + InboundSmtpRole.HEADER_ALLOWANCE);
  }

  private List<MailboxExtensionFactory> extensions() {
    WorkerPool pool = extraction;
    return pool == null
        ? List.of(new SearchIndexFactory())
        : List.of(new SearchIndexFactory(), new AttachmentIndexFactory(pool));
  }

  public static Services start(ShemConfig config) throws IOException, FormatException {
    DataDirectory data = DataDirectory.open(config.dataDirectory());
    try {
      return new Services(config, data, Clock.systemUTC(), secureRandom());
    } catch (IOException | FormatException | RuntimeException e) {
      data.close();
      throw e;
    }
  }

  private static SecureRandom secureRandom() {
    try {
      return SecureRandom.getInstanceStrong();
    } catch (NoSuchAlgorithmException e) {
      return new SecureRandom();
    }
  }

  @Override
  public void close() throws IOException {
    try {
      registry.close();
      WorkerPool pool = extraction;
      if (pool != null) {
        pool.close();
      }
      audit.close();
      background.shutdown();
      indexing.shutdown();
    } finally {
      data.close();
    }
  }
}
