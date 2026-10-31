package org.shem.tls;

import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.jspecify.annotations.Nullable;

/**
 * Issues and renews the listener certificate (ADR 0018). Renewal starts when two thirds of the
 * current certificate's lifetime have passed, minus a per-certificate random jitter of up to a
 * twentieth of the lifetime, so it follows whatever lifetime the CA issues instead of a fixed
 * number of days. Failures back off exponentially from 5 minutes to 6 hours; a failed renewal never
 * touches the still-valid certificate. Every issuance uses a fresh domain key.
 */
public final class CertificateRenewal implements AutoCloseable {
  static final Duration FIRST_BACKOFF = Duration.ofMinutes(5);
  static final Duration MAX_BACKOFF = Duration.ofHours(6);
  static final Duration EXPIRY_WARNING = Duration.ofDays(7);
  private static final System.Logger LOG = System.getLogger(CertificateRenewal.class.getName());

  /** Sanitized renewal state for operators: no keys, tokens, or CA account data. */
  public record Status(
      @Nullable Instant notAfter,
      @Nullable Instant renewAt,
      Instant nextAttempt,
      int consecutiveFailures,
      @Nullable String lastError,
      @Nullable Instant lastSuccess) {}

  private final CertificateGenerations generations;
  private final CertificateAuthority authority;
  private final Http01Challenges challenges;
  private final List<String> hosts;
  private final Clock clock;
  private final SecureRandom random;
  private final ScheduledExecutorService scheduler =
      Executors.newSingleThreadScheduledExecutor(
          Thread.ofPlatform().daemon().name("shem-acme").factory());
  private volatile @Nullable ReloadableTlsContext tls;
  private volatile Status status;
  private @Nullable Instant jitteredFor;
  private Duration jitter = Duration.ZERO;

  public CertificateRenewal(
      CertificateGenerations generations,
      CertificateAuthority authority,
      Http01Challenges challenges,
      List<String> hosts,
      Clock clock,
      SecureRandom random) {
    this.generations = generations;
    this.authority = authority;
    this.challenges = challenges;
    this.hosts = List.copyOf(hosts);
    this.clock = clock;
    this.random = random;
    this.status = new Status(null, null, clock.instant(), 0, null, null);
  }

  /** Listeners to reload after each renewal (absent during first issuance at boot). */
  public void attach(ReloadableTlsContext context) {
    this.tls = context;
  }

  public Status status() {
    return status;
  }

  /**
   * Blocks until a valid certificate is live, retrying with backoff, or until {@code stop} is
   * released. Used at first boot, before any TLS listener exists; only the port-80 challenge
   * listener runs meanwhile. Returns whether a certificate is live.
   */
  public boolean awaitCertificate(java.util.concurrent.CountDownLatch stop)
      throws InterruptedException {
    while (generations.current(clock.instant()).isEmpty()) {
      Duration wait = check();
      if (generations.current(clock.instant()).isEmpty()
          && stop.await(Math.max(1, wait.toMillis()), TimeUnit.MILLISECONDS)) {
        return false;
      }
    }
    return true;
  }

  /** Checks every {@code interval} (and after each attempt as {@link #check()} schedules). */
  public void start(Duration interval) {
    var unused =
        scheduler.scheduleWithFixedDelay(
            this::checkSafely, interval.toMillis(), interval.toMillis(), TimeUnit.MILLISECONDS);
  }

  private void checkSafely() {
    try {
      check();
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    } catch (RuntimeException e) {
      LOG.log(System.Logger.Level.WARNING, "certificate check failed: " + e.getClass().getName());
    }
  }

  /** Renews if due and the backoff has elapsed. Returns how long until the next attempt is due. */
  public synchronized Duration check() throws InterruptedException {
    Instant now = clock.instant();
    Optional<CertificateBundle> live = generations.current(now);
    Status before = status;
    Instant notAfter = live.map(CertificateBundle::notAfter).orElse(null);
    Instant renewAt = live.map(this::renewAt).orElse(null);
    if (renewAt != null && now.isBefore(renewAt)) {
      status = new Status(notAfter, renewAt, renewAt, 0, before.lastError(), before.lastSuccess());
      return Duration.between(now, renewAt);
    }
    if (before.consecutiveFailures() > 0 && now.isBefore(before.nextAttempt())) {
      return Duration.between(now, before.nextAttempt());
    }
    KeyPair domainKey = Pem.newEcKeyPair();
    try {
      List<X509Certificate> chain = authority.issue(hosts, domainKey, challenges);
      CertificateBundle installed = generations.install(chain, domainKey, clock.instant());
      ReloadableTlsContext context = tls;
      if (context != null && !context.reload()) {
        throw new IllegalStateException("listeners rejected the new certificate");
      }
      Instant next = renewAt(installed);
      status = new Status(installed.notAfter(), next, next, 0, null, clock.instant());
      LOG.log(
          System.Logger.Level.INFO,
          "certificate issued; valid until " + installed.notAfter() + ", renewal from " + next);
      return Duration.between(clock.instant(), next);
    } catch (InterruptedException e) {
      throw e;
    } catch (Exception e) {
      int failures = before.consecutiveFailures() + 1;
      Duration backoff = backoff(failures);
      String error = e.getClass().getSimpleName();
      status =
          new Status(notAfter, renewAt, now.plus(backoff), failures, error, before.lastSuccess());
      if (notAfter == null || Duration.between(now, notAfter).compareTo(EXPIRY_WARNING) < 0) {
        LOG.log(
            System.Logger.Level.WARNING,
            "certificate issuance failed ("
                + error
                + "); "
                + (notAfter == null ? "no valid certificate" : "current one expires " + notAfter)
                + "; retry in "
                + backoff);
      } else {
        LOG.log(
            System.Logger.Level.INFO,
            "certificate renewal failed (" + error + "); retry in " + backoff);
      }
      return backoff;
    }
  }

  static Duration backoff(int failures) {
    Duration backoff = FIRST_BACKOFF;
    for (int i = 1; i < failures && backoff.compareTo(MAX_BACKOFF) < 0; i++) {
      backoff = backoff.multipliedBy(2);
    }
    return backoff.compareTo(MAX_BACKOFF) > 0 ? MAX_BACKOFF : backoff;
  }

  /** Two thirds into the lifetime, minus a stable random jitter chosen once per certificate. */
  synchronized Instant renewAt(CertificateBundle bundle) {
    X509Certificate leaf = bundle.chain().get(0);
    Instant notBefore = leaf.getNotBefore().toInstant();
    Duration lifetime = Duration.between(notBefore, bundle.notAfter());
    if (!bundle.notAfter().equals(jitteredFor)) {
      long bound = Math.max(1, lifetime.dividedBy(20).toSeconds());
      jitter = Duration.ofSeconds((long) (random.nextDouble() * bound));
      jitteredFor = bundle.notAfter();
    }
    return notBefore.plus(lifetime.multipliedBy(2).dividedBy(3)).minus(jitter);
  }

  @Override
  public void close() {
    scheduler.shutdownNow();
  }
}
