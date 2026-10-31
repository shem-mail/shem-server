package org.shem.tls;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class CertificateRenewalTest {
  private static final String HOST = "mail.example.org";
  private static final Duration LIFETIME = Duration.ofDays(90);
  @TempDir Path dir;

  static final class MutableClock extends Clock {
    volatile Instant now = Instant.parse("2026-11-01T00:00:00Z");

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
  }

  /** A CA double: issues self-signed certificates, can fail or mis-issue, records challenges. */
  final class FakeAuthority implements CertificateAuthority {
    final List<String> challengeSeen = new ArrayList<>();
    volatile boolean fail;
    volatile String issuedHost = HOST;
    int issued;

    @Override
    public List<X509Certificate> issue(
        List<String> hosts, KeyPair domainKey, Http01Challenges challenges) throws Exception {
      challenges.publish("tok-" + issued, "tok-" + issued + ".thumbprint");
      try {
        challengeSeen.add(challenges.lookup("tok-" + issued).orElse("missing"));
        if (fail) {
          throw new java.io.IOException("CA unreachable");
        }
        issued++;
        return List.of(
            TestCertificates.certificate(
                issuedHost, clock.now.minusSeconds(60), LIFETIME, domainKey));
      } finally {
        challenges.withdraw("tok-" + issued);
        challenges.withdraw("tok-" + (issued - 1));
      }
    }
  }

  private final MutableClock clock = new MutableClock();
  private final Http01Challenges challenges = new Http01Challenges();

  private CertificateRenewal renewal(CertificateGenerations generations, FakeAuthority ca) {
    return new CertificateRenewal(
        generations, ca, challenges, List.of(HOST), clock, new SecureRandom());
  }

  @Test
  void firstIssuanceMakesAValidLiveGenerationWithAnOwnerOnlyKey() throws Exception {
    CertificateGenerations generations =
        new CertificateGenerations(dir.resolve("acme"), List.of(HOST));
    FakeAuthority ca = new FakeAuthority();
    try (CertificateRenewal renewal = renewal(generations, ca)) {
      assertThat(generations.current(clock.now)).isEmpty();
      assertThat(renewal.awaitCertificate(new java.util.concurrent.CountDownLatch(1))).isTrue();
      assertThat(generations.current(clock.now)).isPresent();
      assertThat(ca.challengeSeen).containsExactly("tok-0.thumbprint");
      assertThat(challenges.size()).as("tokens withdrawn after the order").isZero();
      assertThat(Files.isSymbolicLink(dir.resolve("acme/live"))).isTrue();
      assertThat(Files.getPosixFilePermissions(generations.keyFile()))
          .containsExactlyInAnyOrder(
              PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
      CertificateRenewal.Status status = renewal.status();
      assertThat(status.consecutiveFailures()).isZero();
      assertThat(status.renewAt())
          .isBetween(
              clock
                  .now
                  .plus(LIFETIME.multipliedBy(2).dividedBy(3))
                  .minus(LIFETIME.dividedBy(20))
                  .minusSeconds(61),
              clock.now.plus(LIFETIME.multipliedBy(2).dividedBy(3)));
    }
  }

  @Test
  void renewsOnlyWhenDueAndUsesAFreshKey() throws Exception {
    CertificateGenerations generations =
        new CertificateGenerations(dir.resolve("acme"), List.of(HOST));
    FakeAuthority ca = new FakeAuthority();
    try (CertificateRenewal renewal = renewal(generations, ca)) {
      renewal.check();
      X509Certificate first = generations.current(clock.now).orElseThrow().chain().get(0);
      clock.now = clock.now.plus(Duration.ofDays(30));
      renewal.check();
      assertThat(ca.issued).as("not due yet").isEqualTo(1);

      clock.now = clock.now.plus(Duration.ofDays(31));
      renewal.check();
      assertThat(ca.issued).isEqualTo(2);
      X509Certificate second = generations.current(clock.now).orElseThrow().chain().get(0);
      assertThat(second.getPublicKey()).isNotEqualTo(first.getPublicKey());
      assertThat(generations.latestGeneration()).isEqualTo(2);
    }
  }

  @Test
  void failedRenewalKeepsTheCurrentCertificateAndBacksOff() throws Exception {
    CertificateGenerations generations =
        new CertificateGenerations(dir.resolve("acme"), List.of(HOST));
    FakeAuthority ca = new FakeAuthority();
    try (CertificateRenewal renewal = renewal(generations, ca)) {
      renewal.check();
      X509Certificate live = generations.current(clock.now).orElseThrow().chain().get(0);
      clock.now = clock.now.plus(Duration.ofDays(70));
      ca.fail = true;
      assertThat(renewal.check()).isEqualTo(CertificateRenewal.FIRST_BACKOFF);
      assertThat(renewal.status().consecutiveFailures()).isEqualTo(1);
      assertThat(renewal.status().lastError()).isEqualTo("IOException");
      assertThat(generations.current(clock.now).orElseThrow().chain().get(0)).isEqualTo(live);

      int attempts = ca.challengeSeen.size();
      renewal.check();
      assertThat(ca.challengeSeen).as("backoff not yet elapsed").hasSize(attempts);
      clock.now = clock.now.plus(CertificateRenewal.FIRST_BACKOFF);
      assertThat(renewal.check()).isEqualTo(Duration.ofMinutes(10));

      ca.fail = false;
      clock.now = clock.now.plus(Duration.ofMinutes(10));
      renewal.check();
      assertThat(renewal.status().consecutiveFailures()).isZero();
      assertThat(generations.current(clock.now).orElseThrow().chain().get(0)).isNotEqualTo(live);
    }
  }

  @Test
  void backoffIsCapped() {
    assertThat(CertificateRenewal.backoff(1)).isEqualTo(Duration.ofMinutes(5));
    assertThat(CertificateRenewal.backoff(3)).isEqualTo(Duration.ofMinutes(20));
    assertThat(CertificateRenewal.backoff(40)).isEqualTo(CertificateRenewal.MAX_BACKOFF);
  }

  @Test
  void aCertificateForTheWrongHostIsNeverMadeLive() throws Exception {
    CertificateGenerations generations =
        new CertificateGenerations(dir.resolve("acme"), List.of(HOST));
    FakeAuthority ca = new FakeAuthority();
    try (CertificateRenewal renewal = renewal(generations, ca)) {
      renewal.check();
      Path liveTarget = Files.readSymbolicLink(dir.resolve("acme/live"));
      clock.now = clock.now.plus(Duration.ofDays(70));
      ca.issuedHost = "evil.example";
      renewal.check();
      assertThat(renewal.status().lastError()).isEqualTo("InvalidCertificateException");
      assertThat(Files.readSymbolicLink(dir.resolve("acme/live"))).isEqualTo(liveTarget);
      assertThat(Files.exists(dir.resolve("acme/gen-2")))
          .as("rejected generation removed")
          .isFalse();
    }
  }

  @Test
  void aCrashBeforeTheSwapLeavesTheOldGenerationLive() throws Exception {
    CertificateGenerations generations =
        new CertificateGenerations(dir.resolve("acme"), List.of(HOST));
    FakeAuthority ca = new FakeAuthority();
    try (CertificateRenewal renewal = renewal(generations, ca)) {
      renewal.check();
    }
    X509Certificate live = generations.current(clock.now).orElseThrow().chain().get(0);
    // Simulate a crash after a new generation was partially written: key present, no chain.
    Path partial = dir.resolve("acme/gen-2");
    Files.createDirectories(partial);
    Files.writeString(partial.resolve("key.pem"), "partial");
    assertThat(generations.current(clock.now).orElseThrow().chain().get(0)).isEqualTo(live);
    // The next install skips past the abandoned generation and prunes older ones.
    KeyPair key = Pem.newEcKeyPair();
    generations.install(
        List.of(TestCertificates.certificate(HOST, clock.now, LIFETIME, key)), key, clock.now);
    assertThat(Files.readSymbolicLink(dir.resolve("acme/live")).toString()).isEqualTo("gen-3");
    assertThat(Files.exists(dir.resolve("acme/gen-1"))).isFalse();
  }

  @Test
  void accountKeysRoundTripThroughTheirFile() throws Exception {
    Acme4jAuthority authority =
        new Acme4jAuthority(
            java.net.URI.create("https://acme.invalid/directory"),
            dir.resolve("acme/account.pem"),
            null);
    KeyPair created = authority.accountKey();
    KeyPair loaded = authority.accountKey();
    assertThat(loaded.getPublic()).isEqualTo(created.getPublic());
    assertThat(loaded.getPrivate()).isEqualTo(created.getPrivate());
    assertThat(Files.getPosixFilePermissions(dir.resolve("acme/account.pem")))
        .containsExactlyInAnyOrder(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
  }

  @Test
  void challengeTokensAreValidatedAndBounded() {
    assertThatThrownBy(() -> challenges.publish("../etc", "x"))
        .isInstanceOf(IllegalArgumentException.class);
    assertThat(challenges.lookup("../etc")).isEmpty();
    for (int i = 0; i < Http01Challenges.MAX_ACTIVE; i++) {
      challenges.publish("t" + i, "a");
    }
    assertThatThrownBy(() -> challenges.publish("one-more", "a"))
        .isInstanceOf(IllegalStateException.class);
  }

  @Test
  void anUnreachableCaIsAReportedFailureNotACrash() throws Exception {
    CertificateGenerations generations =
        new CertificateGenerations(dir.resolve("acme"), List.of(HOST));
    int port;
    try (java.net.ServerSocket probe = new java.net.ServerSocket(0)) {
      port = probe.getLocalPort();
    }
    Acme4jAuthority authority =
        new Acme4jAuthority(
            java.net.URI.create("https://127.0.0.1:" + port + "/directory"),
            generations.accountKeyFile(),
            null);
    try (CertificateRenewal renewal =
        new CertificateRenewal(
            generations, authority, challenges, List.of(HOST), clock, new SecureRandom())) {
      assertThat(renewal.check()).isEqualTo(CertificateRenewal.FIRST_BACKOFF);
      assertThat(renewal.status().consecutiveFailures()).isEqualTo(1);
      assertThat(renewal.status().lastError()).startsWith("Acme");
      assertThat(generations.current(clock.now)).isEmpty();
    }
  }
}
