package net.shem.app;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import net.shem.common.FaultInjector;
import net.shem.common.FormatException;
import net.shem.common.IdGenerator;
import net.shem.crypto.Argon2Parameters;
import net.shem.crypto.Argon2idKdf;
import net.shem.crypto.KdfAdmission;
import net.shem.delivery.DeliveryService;
import net.shem.extract.ExtractionSettings;
import net.shem.extract.WorkerPool;
import net.shem.identity.AdminStore;
import net.shem.identity.AuditLog;
import net.shem.identity.DeliveryPolicy;
import net.shem.identity.IdentityService;
import net.shem.identity.QuotaLedger;
import net.shem.mailbox.AttemptLimiter;
import net.shem.mailbox.KeyLifecycle;
import net.shem.mailbox.MailboxExtensionFactory;
import net.shem.mailbox.MailboxProvisioning;
import net.shem.mailbox.MailboxRegistry;
import net.shem.mailbox.SessionService;
import net.shem.search.AttachmentIndexFactory;
import net.shem.search.SearchIndexFactory;
import net.shem.smtp.InboundSmtpRole;
import net.shem.store.BlobStore;
import net.shem.store.MailboxPaths;
import net.shem.store.ReceiptStore;
import net.shem.store.metadata.MetadataStore;
import org.jspecify.annotations.Nullable;

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
