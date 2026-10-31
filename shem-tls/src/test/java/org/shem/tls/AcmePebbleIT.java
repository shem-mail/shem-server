package org.shem.tls;

import static org.assertj.core.api.Assertions.assertThat;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.api.io.TempDir;

/**
 * Real ACME round trip against a local Pebble test CA (ADR 0018). Opt-in, because it needs Pebble
 * running outside the build:
 *
 * <pre>
 *   pebble -config test/config/pebble-config.json   # httpPort 5002, VA reaching this host
 *   mvn -pl shem-tls verify -Dit.test=AcmePebbleIT \
 *       -Dshem.pebble.directory=acme://pebble -Dshem.pebble.host=localhost
 * </pre>
 *
 * {@code acme://pebble} makes acme4j trust Pebble's built-in test root. The test serves HTTP-01
 * tokens on {@code shem.pebble.challengePort} (default 5002) exactly as the port-80 listener does.
 */
@EnabledIfSystemProperty(named = "shem.pebble.directory", matches = ".+")
class AcmePebbleIT {
  @TempDir Path dir;

  @Test
  void issuesAndInstallsACertificateThroughHttp01() throws Exception {
    String host = System.getProperty("shem.pebble.host", "localhost");
    int port = Integer.getInteger("shem.pebble.challengePort", 5002);
    Http01Challenges challenges = new Http01Challenges();
    HttpServer server = HttpServer.create(new InetSocketAddress(port), 16);
    server.createContext(
        Http01Challenges.PATH_PREFIX,
        exchange -> {
          try (exchange) {
            String token =
                exchange.getRequestURI().getPath().substring(Http01Challenges.PATH_PREFIX.length());
            var answer = challenges.lookup(token);
            if (answer.isEmpty()) {
              exchange.sendResponseHeaders(404, -1);
              return;
            }
            byte[] body = answer.get().getBytes(StandardCharsets.US_ASCII);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
          }
        });
    server.start();
    try {
      CertificateGenerations generations =
          new CertificateGenerations(dir.resolve("acme"), List.of(host));
      Acme4jAuthority authority =
          new Acme4jAuthority(
              URI.create(System.getProperty("shem.pebble.directory")),
              generations.accountKeyFile(),
              null);
      KeyPair key = Pem.newEcKeyPair();
      List<X509Certificate> chain = authority.issue(List.of(host), key, challenges);
      assertThat(challenges.size()).isZero();
      CertificateBundle installed = generations.install(chain, key, Instant.now());
      assertThat(installed.notAfter()).isAfter(Instant.now());
      assertThat(generations.current(Instant.now())).isPresent();
      // A second order reuses the persisted account key.
      KeyPair next = Pem.newEcKeyPair();
      generations.install(authority.issue(List.of(host), next, challenges), next, Instant.now());
      assertThat(generations.latestGeneration()).isEqualTo(2);
    } finally {
      server.stop(0);
    }
  }
}
