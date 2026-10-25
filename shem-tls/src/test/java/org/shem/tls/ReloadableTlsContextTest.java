package org.shem.tls;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ReloadableTlsContextTest {
  private static final String HOST = "mail.example.org";
  @TempDir Path dir;

  private static Instant now() {
    return Instant.now().minus(Duration.ofMinutes(1));
  }

  @Test
  void hotReloadServesNewCertificateToNewHandshakesOnly() throws Exception {
    TestCertificates.Files2 first = TestCertificates.write(dir, HOST, now(), Duration.ofDays(30));
    ReloadableTlsContext tls =
        ReloadableTlsContext.open(first.chain(), first.key(), List.of(HOST), Clock.systemUTC());
    try (SSLServerSocket server =
        (SSLServerSocket) tls.sslContext().getServerSocketFactory().createServerSocket(0)) {
      server.setSSLParameters(tls.serverParameters());
      Thread acceptor = Thread.ofVirtual().start(() -> echo(server, 2));
      SSLContext trustBoth;
      try (SSLSocket established =
          connect(server, TestCertificates.clientTrusting(first.certificate()))) {
        assertThat(peer(established)).isEqualTo(first.certificate());
        TestCertificates.Files2 second =
            TestCertificates.write(dir, HOST, now(), Duration.ofDays(60));
        assertThat(tls.reload()).isTrue();
        trustBoth = TestCertificates.clientTrusting(first.certificate(), second.certificate());
        try (SSLSocket fresh = connect(server, trustBoth)) {
          assertThat(peer(fresh)).isEqualTo(second.certificate());
        }
        // The established session keeps working after the reload.
        established.getOutputStream().write('x');
        assertThat(established.getInputStream().read()).isEqualTo('x');
      }
      acceptor.join(5_000);
    }
  }

  @Test
  void invalidReplacementsAreRejectedAndCurrentCertificateKept() throws Exception {
    TestCertificates.Files2 good = TestCertificates.write(dir, HOST, now(), Duration.ofDays(30));
    ReloadableTlsContext tls =
        ReloadableTlsContext.open(good.chain(), good.key(), List.of(HOST), Clock.systemUTC());
    Instant expiry = tls.notAfter();

    KeyPair a = ec();
    KeyPair b = ec();
    TestCertificates.write(dir, HOST, now(), Duration.ofDays(90), a, b); // key mismatch
    assertThat(tls.reload()).isFalse();
    assertThat(tls.lastFailure()).contains("does not match");

    TestCertificates.write(dir, "other.example.net", now(), Duration.ofDays(90)); // wrong host
    assertThat(tls.reload()).isFalse();

    TestCertificates.write(
        dir, HOST, Instant.now().minus(Duration.ofDays(10)), Duration.ofDays(1)); // expired
    assertThat(tls.reload()).isFalse();
    assertThat(tls.notAfter()).isEqualTo(expiry);
  }

  @Test
  void startupFailsWithoutValidCertificate() throws Exception {
    TestCertificates.Files2 expired =
        TestCertificates.write(
            dir, HOST, Instant.now().minus(Duration.ofDays(10)), Duration.ofDays(1));
    assertThatThrownBy(
            () ->
                ReloadableTlsContext.open(
                    expired.chain(), expired.key(), List.of(HOST), Clock.systemUTC()))
        .isInstanceOf(CertificateBundle.InvalidCertificateException.class);
  }

  @Test
  void wildcardCoverage() {
    assertThat(CertificateBundle.covers(List.of("*.example.org"), "mail.example.org")).isTrue();
    assertThat(CertificateBundle.covers(List.of("*.example.org"), "a.b.example.org")).isFalse();
    assertThat(CertificateBundle.covers(List.of("*.example.org"), "example.org")).isFalse();
  }

  @Test
  void watcherReloadsOnFileChange() throws Exception {
    TestCertificates.Files2 first = TestCertificates.write(dir, HOST, now(), Duration.ofDays(30));
    ReloadableTlsContext tls =
        ReloadableTlsContext.open(first.chain(), first.key(), List.of(HOST), Clock.systemUTC());
    try (CertificateWatcher watcher =
        new CertificateWatcher(tls, first.chain(), first.key(), Duration.ofHours(1))) {
      assertThat(watcher.check()).isFalse();
      Thread.sleep(20); // distinct mtime on coarse filesystems
      TestCertificates.write(dir, HOST, now(), Duration.ofDays(77));
      java.nio.file.Files.setLastModifiedTime(
          first.chain(), java.nio.file.attribute.FileTime.from(Instant.now().plusSeconds(5)));
      assertThat(watcher.check()).isTrue();
      assertThat(tls.notAfter()).isAfter(Instant.now().plus(Duration.ofDays(70)));
    }
  }

  private static KeyPair ec() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec("secp256r1"));
    return generator.generateKeyPair();
  }

  private static SSLSocket connect(SSLServerSocket server, SSLContext client) throws Exception {
    SSLSocket socket =
        (SSLSocket) client.getSocketFactory().createSocket("localhost", server.getLocalPort());
    socket.startHandshake();
    return socket;
  }

  private static X509Certificate peer(SSLSocket socket) throws Exception {
    return (X509Certificate) socket.getSession().getPeerCertificates()[0];
  }

  private static void echo(SSLServerSocket server, int connections) {
    for (int i = 0; i < connections; i++) {
      try {
        SSLSocket socket = (SSLSocket) server.accept();
        Thread.ofVirtual()
            .start(
                () -> {
                  try (socket;
                      InputStream in = socket.getInputStream();
                      OutputStream out = socket.getOutputStream()) {
                    int b;
                    while ((b = in.read()) >= 0) {
                      out.write(b);
                      out.flush();
                    }
                  } catch (Exception ignored) {
                    // client closed
                  }
                });
      } catch (Exception e) {
        return;
      }
    }
  }
}
