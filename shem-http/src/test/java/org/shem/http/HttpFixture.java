package org.shem.http;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.jspecify.annotations.Nullable;
import org.shem.common.FaultInjector;
import org.shem.common.IdGenerator;
import org.shem.crypto.Argon2Parameters;
import org.shem.crypto.Argon2idKdf;
import org.shem.crypto.KdfAdmission;
import org.shem.crypto.Secret;
import org.shem.identity.AdminStore;
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
import org.shem.store.MailboxPaths;
import org.shem.store.ReceiptStore;
import org.shem.store.metadata.MetadataStore;
import org.shem.tls.ReloadableTlsContext;
import org.shem.tls.TestCertificates;

/** A real HTTPS API over the mailbox services, with a controllable clock. */
final class HttpFixture implements AutoCloseable {
  static final SecureRandom RANDOM = new SecureRandom();
  static final String ORIGIN = "https://localhost";
  static final String ALICE = "alice@example.org";
  static final String PASSWORD = "correct horse battery staple";
  static final Duration IDLE = Duration.ofMinutes(30);
  static final Duration STEP_UP = Duration.ofMinutes(5);
  static final MtaStsPolicy MTA_STS =
      new MtaStsPolicy(MtaStsPolicy.Mode.TESTING, List.of("mx.example.org"), Duration.ofDays(7));

  static final class MutableClock extends Clock {
    volatile Instant now = Instant.now();

    @Override
    public ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      return now;
    }

    void advance(Duration duration) {
      now = now.plus(duration);
    }
  }

  /** A response with its headers and body text. */
  record Response(int status, String body, HttpResponse<String> raw) {
    @Nullable String header(String name) {
      return raw.headers().firstValue(name).orElse(null);
    }
  }

  final MutableClock clock = new MutableClock();
  final IdentityService identity;
  final MailboxRegistry registry;
  final SessionService sessions;
  final KeyLifecycle lifecycle;
  final MailboxProvisioning provisioning;
  final AdminStore admins;
  final org.shem.identity.AuditLog audit;
  final FakeDkim dkim = new FakeDkim();

  /** Attachment "extraction" for tests: UTF-8 text, or encrypted for {@code x-locked}. */
  static final class FakeExtractor implements org.shem.search.AttachmentExtractor {
    volatile boolean available = true;

    @Override
    public Outcome extract(
        java.io.InputStream content, @Nullable String type, @Nullable String extension)
        throws UnavailableException, java.io.IOException {
      if (!available) {
        throw new UnavailableException("no worker");
      }
      String text = new String(content.readAllBytes(), StandardCharsets.UTF_8);
      return "application/x-locked".equals(type)
          ? new Outcome.Encrypted()
          : new Outcome.Text(text, false);
    }
  }

  final FakeExtractor attachments = new FakeExtractor();

  /** What the admin TLS route reports; tests replace it. */
  volatile org.shem.tls.CertificateRenewal.Status certificateStatus =
      new org.shem.tls.CertificateRenewal.Status(
          Instant.parse("2027-01-01T00:00:00Z"),
          Instant.parse("2026-12-01T00:00:00Z"),
          Instant.parse("2026-12-01T00:00:00Z"),
          0,
          null,
          null);

  final HttpRole http;
  final HttpClient client;
  final String base;

  static final String ADMIN = "root";
  static final String ADMIN_PASSWORD = "admin password that is long";

  /** The administrator's TOTP secret (created at setup). */
  final Secret adminTotp;

  /** In-memory DKIM keys: the TXT value is derived from the selector. */
  static final class FakeDkim implements DkimKeys {
    final java.util.Map<String, String> keys = new java.util.concurrent.ConcurrentHashMap<>();

    @Override
    public String generate(String selector, String domain) throws Exception {
      String record = "v=DKIM1; k=rsa; p=" + selector;
      if (keys.putIfAbsent(selector + "." + domain, record) != null) {
        throw new java.nio.file.FileAlreadyExistsException(selector);
      }
      return record;
    }

    @Override
    public java.util.Optional<String> publishedRecord(String selector, String domain) {
      return java.util.Optional.ofNullable(keys.get(selector + "." + domain));
    }
  }

  /** Alice's TOTP secret (registered at setup). */
  final Secret aliceTotp = org.shem.crypto.Totp.generateSecret(RANDOM);

  private final ExecutorService background = Executors.newFixedThreadPool(2);

  HttpFixture(Path root) throws Exception {
    IdGenerator ids = IdGenerator.secure(RANDOM);
    MailboxPaths paths = new MailboxPaths(root.resolve("mailboxes"));
    identity =
        IdentityService.open(
            root.resolve("routing/directory.bin"),
            clock,
            ids,
            DeliveryPolicy.DEFAULT,
            Duration.ofDays(30));
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
                new BlobStore(paths, ids, RANDOM, FaultInjector.NONE),
                new ReceiptStore(paths, ids, RANDOM, clock, FaultInjector.NONE),
                new QuotaLedger(paths::mailbox),
                identity,
                env,
                10 << 20,
                List.of(new org.shem.search.AttachmentIndexFactory(attachments)),
                background),
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
    provisioning = new MailboxProvisioning(identity, paths, kdf, cheap, env, ids, RANDOM, clock);
    admins = AdminStore.open(root.resolve("admin/admins.bin"), kdf, cheap, ids, RANDOM, clock);
    audit = org.shem.identity.AuditLog.open(root.resolve("audit/audit.log"), clock, null);
    adminTotp = admins.create(ADMIN, ADMIN_PASSWORD);
    identity.createDomain("example.org");
    String bootstrap = provision(ALICE);
    try (MailboxLease lease =
        sessions.authenticate(
            ALICE, bootstrap, InetAddress.getLoopbackAddress(), Capability.ENROLL)) {
      lifecycle.enroll(lease, PASSWORD);
    }
    try (MailboxLease lease =
        sessions.authenticatePrimary(ALICE, PASSWORD, InetAddress.getLoopbackAddress())) {
      lifecycle.addFactor(
          lease,
          new org.shem.crypto.MfaFactor(
              org.shem.common.OpaqueId.random(RANDOM),
              org.shem.crypto.MfaFactor.Kind.TOTP,
              "phone",
              clock.instant(),
              0,
              aliceTotp.copy()));
    }
    TestCertificates.Files2 certificate =
        TestCertificates.write(
            root.resolve("tls"), "localhost", Instant.now().minusSeconds(60), Duration.ofDays(30));
    ReloadableTlsContext tls =
        ReloadableTlsContext.open(
            certificate.chain(), certificate.key(), List.of("localhost"), Clock.systemUTC());
    http =
        HttpRole.start(
            new HttpSettings(
                new InetSocketAddress(InetAddress.getLoopbackAddress(), 0),
                ORIGIN,
                16,
                16 * 1024,
                100,
                3,
                IDLE,
                Duration.ofHours(12),
                STEP_UP,
                MTA_STS),
            sessions,
            lifecycle,
            identity,
            new AdminApi.Services(
                admins,
                identity,
                provisioning,
                dkim,
                Duration.ofDays(1),
                "mx.example.org",
                () -> certificateStatus,
                audit),
            tls,
            RANDOM,
            clock);
    client =
        HttpClient.newBuilder()
            .sslContext(TestCertificates.clientTrusting(certificate.certificate()))
            .proxy(java.net.ProxySelector.of(null))
            .build();
    base = "https://localhost:" + http.port();
  }

  /** A fresh TOTP code: advances the clock one step so codes are never replays. */
  String totp(Secret secret) throws Exception {
    clock.advance(Duration.ofSeconds(org.shem.crypto.Totp.STEP_SECONDS));
    return org.shem.crypto.Totp.code(
        secret, clock.instant().getEpochSecond() / org.shem.crypto.Totp.STEP_SECONDS);
  }

  /** Provisions an account and returns its bootstrap password. */
  String provision(String address) throws Exception {
    MailboxProvisioning.Provisioned p =
        provisioning.provision(EmailAddress.parse(address), 0, Duration.ofDays(1));
    try (Secret secret = p.bootstrapPassword()) {
      return new String(secret.exposeCopy(), StandardCharsets.UTF_8);
    }
  }

  Response call(String method, String path, @Nullable String json, String... headers)
      throws Exception {
    HttpRequest.Builder request =
        HttpRequest.newBuilder(URI.create(base + path))
            .method(
                method,
                json == null
                    ? HttpRequest.BodyPublishers.noBody()
                    : HttpRequest.BodyPublishers.ofString(json));
    List<String> all = new ArrayList<>(List.of(headers));
    if (json != null && !all.contains("Content-Type")) {
      all.add("Content-Type");
      all.add("application/json");
    }
    for (int i = 0; i + 1 < all.size(); i += 2) {
      request.header(all.get(i), all.get(i + 1));
    }
    HttpResponse<String> response =
        client.send(request.build(), HttpResponse.BodyHandlers.ofString());
    return new Response(response.statusCode(), response.body(), response);
  }

  @Override
  public void close() {
    http.close();
    try {
      audit.close();
    } catch (java.io.IOException e) {
      throw new java.io.UncheckedIOException(e);
    }
    registry.close();
    background.shutdownNow();
  }
}
