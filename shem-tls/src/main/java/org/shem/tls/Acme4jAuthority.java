package org.shem.tls;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.jspecify.annotations.Nullable;
import org.shem.common.DurableFiles;
import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.AccountBuilder;
import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Order;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.exception.AcmeException;

/**
 * ACME (RFC 8555) through acme4j with the HTTP-01 challenge. The account key is created once and
 * kept owner-only next to the certificate generations; it never leaves the TLS role. The operator
 * must accept the CA's terms explicitly in configuration.
 */
public final class Acme4jAuthority implements CertificateAuthority {
  static final Duration WAIT = Duration.ofMinutes(2);

  private final URI directory;
  private final Path accountKeyFile;
  private final @Nullable String email;

  public Acme4jAuthority(URI directory, Path accountKeyFile, @Nullable String email) {
    this.directory = directory;
    this.accountKeyFile = accountKeyFile;
    this.email = email;
  }

  @Override
  public List<X509Certificate> issue(
      List<String> hosts, KeyPair domainKey, Http01Challenges challenges)
      throws AcmeException, IOException, InterruptedException {
    Session session = new Session(directory);
    AccountBuilder builder = new AccountBuilder().agreeToTermsOfService().useKeyPair(accountKey());
    if (email != null) {
      builder.addEmail(email);
    }
    Account account = builder.create(session);
    Order order = account.newOrder().domains(hosts).create();
    List<String> published = new ArrayList<>();
    try {
      for (Authorization authorization : order.getAuthorizations()) {
        if (authorization.getStatus() == Status.VALID) {
          continue;
        }
        Http01Challenge challenge =
            authorization
                .findChallenge(Http01Challenge.class)
                .orElseThrow(() -> new AcmeException("CA offers no HTTP-01 challenge"));
        challenges.publish(challenge.getToken(), challenge.getAuthorization());
        published.add(challenge.getToken());
        challenge.trigger();
        if (authorization.waitForCompletion(WAIT) != Status.VALID) {
          throw new AcmeException("authorization was not validated");
        }
      }
    } finally {
      published.forEach(challenges::withdraw);
    }
    if (order.waitUntilReady(WAIT) != Status.READY) {
      throw new AcmeException("order did not become ready");
    }
    order.execute(domainKey);
    if (order.waitForCompletion(WAIT) != Status.VALID) {
      throw new AcmeException("order was not completed");
    }
    return order.getCertificate().getCertificateChain();
  }

  /** Loads the account key, creating it (EC P-256, owner-only) on first use. */
  KeyPair accountKey() throws IOException {
    if (Files.exists(accountKeyFile)) {
      return Pem.readKeyPair(Files.readString(accountKeyFile, StandardCharsets.US_ASCII));
    }
    KeyPair pair = Pem.newEcKeyPair();
    DurableFiles.createPrivateDirectories(
        java.util.Objects.requireNonNull(accountKeyFile.getParent()));
    DurableFiles.writeNew(accountKeyFile, Pem.keyPair(pair).getBytes(StandardCharsets.US_ASCII));
    return pair;
  }
}
