package org.shem.outbound;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import javax.net.ssl.SSLContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.shem.delivery.MessageSource;
import org.shem.tls.ReloadableTlsContext;
import org.shem.tls.TestCertificates;

@SuppressWarnings(
    "StringConcatToTextBlock") // explicit CRLF line endings read better as concatenation
class OutboundDeliveryTest {
  private static final String MESSAGE =
      "From: alice@example.org\r\nTo: bob@remote.test\r\nSubject: hi\r\n\r\n.leading dot\r\nbody\r\n";
  @TempDir Path dir;
  private OutboundFixture fixture;
  private @org.jspecify.annotations.Nullable FakeSmtpPeer peer;
  private TestCertificates.Files2 certificate;

  @BeforeEach
  void setUp() throws Exception {
    fixture = new OutboundFixture(dir);
    certificate =
        TestCertificates.write(
            dir.resolve("tls"), "localhost", Instant.now().minusSeconds(60), Duration.ofDays(30));
  }

  @AfterEach
  void tearDown() throws Exception {
    FakeSmtpPeer current = peer;
    if (current != null) {
      current.close();
    }
  }

  private FakeSmtpPeer peer() {
    return java.util.Objects.requireNonNull(peer);
  }

  private SSLContext serverTls() throws Exception {
    return ReloadableTlsContext.open(
            certificate.chain(),
            certificate.key(),
            List.of("localhost"),
            java.time.Clock.systemUTC())
        .sslContext();
  }

  private SSLContext trusting() throws Exception {
    return TestCertificates.clientTrusting(certificate.certificate());
  }

  private QueueItem enqueue(String... recipients) throws Exception {
    return fixture.queue.enqueue(
        OutboundFixture.SENDER,
        List.of(recipients),
        MessageSource.ofBytes(MESSAGE.getBytes(StandardCharsets.UTF_8)));
  }

  @Test
  void deliversOverOpportunisticTlsWithoutAnyMailboxKey() throws Exception {
    peer = new FakeSmtpPeer(serverTls());
    fixture.dns.put("remote.test/MX", List.of("10 127.0.0.1"));
    QueueItem item = enqueue("bob@remote.test", "carol@remote.test");
    try (OutboundDelivery delivery =
        fixture.delivery(fixture.queue, peer().port(), SSLContext.getDefault())) {
      delivery.runDueNow();
      assertThat(delivery.deliveredCount()).isEqualTo(2);
    }
    assertThat(peer().received).hasSize(1);
    FakeSmtpPeer.Received received = peer().received.getFirst();
    assertThat(received.tls()).as("self-signed certificate accepted opportunistically").isTrue();
    assertThat(received.from()).isEqualTo(OutboundFixture.SENDER);
    assertThat(received.to()).containsExactly("bob@remote.test", "carol@remote.test");
    assertThat(received.text()).isEqualTo(MESSAGE);
    assertThat(fixture.queue.get(item.id())).as("finished items are removed").isEmpty();
    assertThat(fixture.localDeliveries).isEmpty();
  }

  @Test
  void permanentRejectionProducesOneDsnToTheLocalSender() throws Exception {
    peer = new FakeSmtpPeer(null);
    peer().rcptReply = rcpt -> rcpt.startsWith("nobody") ? "550 5.1.1 no such user" : "250 OK";
    fixture.dns.put("remote.test/MX", List.of("10 127.0.0.1"));
    enqueue("bob@remote.test", "nobody@remote.test");
    try (OutboundDelivery delivery =
        fixture.delivery(fixture.queue, peer().port(), SSLContext.getDefault())) {
      delivery.runDueNow();
      assertThat(delivery.failedCount()).isEqualTo(1);
    }
    assertThat(peer().received.getFirst().to()).containsExactly("bob@remote.test");
    assertThat(fixture.localDeliveries).containsExactly(fixture.senderMailbox);
    assertThat(fixture.queue.size()).isZero();
  }

  @Test
  void temporaryFailuresAreRetriedOnScheduleAndSurviveRestart() throws Exception {
    peer = new FakeSmtpPeer(null);
    peer().rcptReply = rcpt -> "451 4.7.1 try later";
    fixture.dns.put("remote.test/MX", List.of("10 127.0.0.1"));
    QueueItem item = enqueue("bob@remote.test");
    try (OutboundDelivery delivery =
        fixture.delivery(fixture.queue, peer().port(), SSLContext.getDefault())) {
      delivery.runDueNow();
    }
    QueueItem deferred = fixture.queue.get(item.id()).orElseThrow();
    assertThat(deferred.attempts()).isEqualTo(1);
    assertThat(deferred.nextAttempt()).isEqualTo(fixture.clock.now.plus(Duration.ofMinutes(5)));
    assertThat(deferred.pending().getFirst().lastReply()).isEqualTo("451 4.7.1");

    peer().rcptReply = rcpt -> "250 OK";
    OutboundQueue reopened = fixture.openQueue();
    try (OutboundDelivery delivery =
        fixture.delivery(reopened, peer().port(), SSLContext.getDefault())) {
      delivery.runDueNow();
      assertThat(peer().received).as("not due yet").isEmpty();
      fixture.clock.now = fixture.clock.now.plus(Duration.ofMinutes(6));
      delivery.runDueNow();
    }
    assertThat(peer().received).hasSize(1);
    assertThat(reopened.size()).isZero();
  }

  @Test
  void mxFallbackNullMxAndImplicitMx() throws Exception {
    peer = new FakeSmtpPeer(null);
    // 127.0.0.2 has no listener: the second MX is used.
    fixture.dns.put("remote.test/MX", List.of("20 127.0.0.1", "10 127.0.0.2"));
    fixture.dns.put("nomail.test/MX", List.of("0 ."));
    enqueue("bob@remote.test", "x@nomail.test", "y@127.0.0.1");
    try (OutboundDelivery delivery =
        fixture.delivery(fixture.queue, peer().port(), SSLContext.getDefault())) {
      delivery.runDueNow();
    }
    assertThat(peer().received).hasSize(2);
    assertThat(peer().received)
        .flatExtracting(FakeSmtpPeer.Received::to)
        .containsExactlyInAnyOrder("bob@remote.test", "y@127.0.0.1");
    assertThat(fixture.localDeliveries).as("DSN for the null-MX recipient").hasSize(1);
  }

  @Test
  void expiredItemsFailWithADsn() throws Exception {
    fixture.dns.put("FAIL remote.test", List.of());
    enqueue("bob@remote.test");
    fixture.clock.now = fixture.clock.now.plus(Duration.ofDays(6));
    try (OutboundDelivery delivery = fixture.delivery(fixture.queue, 1, SSLContext.getDefault())) {
      delivery.runDueNow();
    }
    assertThat(fixture.localDeliveries).hasSize(1);
    assertThat(fixture.queue.size()).isZero();
  }

  @Test
  void enforcedMtaStsNeverDowngrades() throws Exception {
    fixture.dns.put("remote.test/MX", List.of("10 localhost"));
    fixture.dns.put("_mta-sts.remote.test/TXT", List.of("v=STSv1; id=20261025"));
    fixture.policies.put(
        "remote.test", "version: STSv1\nmode: enforce\nmx: localhost\nmax_age: 86400\n");

    // A peer without STARTTLS: deferred, not sent in plaintext.
    peer = new FakeSmtpPeer(null);
    QueueItem item = enqueue("bob@remote.test");
    try (OutboundDelivery delivery = fixture.delivery(fixture.queue, peer().port(), trusting())) {
      delivery.runDueNow();
    }
    assertThat(peer().received).isEmpty();
    assertThat(fixture.queue.get(item.id()).orElseThrow().pending().getFirst().lastReply())
        .isEqualTo("mta-sts-no-tls");
    peer().close();

    // STARTTLS with a certificate the verifier does not trust: still deferred.
    peer = new FakeSmtpPeer(serverTls());
    fixture.clock.now = fixture.clock.now.plus(Duration.ofMinutes(6));
    try (OutboundDelivery delivery =
        fixture.delivery(fixture.queue, peer().port(), SSLContext.getDefault())) {
      delivery.runDueNow();
    }
    assertThat(peer().received).isEmpty();

    // A valid certificate for the MX name: delivered over TLS.
    fixture.clock.now = fixture.clock.now.plus(Duration.ofMinutes(31));
    try (OutboundDelivery delivery = fixture.delivery(fixture.queue, peer().port(), trusting())) {
      delivery.runDueNow();
    }
    assertThat(peer().received).hasSize(1);
    assertThat(peer().received.getFirst().tls()).isTrue();
  }

  @Test
  void mtaStsExcludesUnlistedMxHosts() throws Exception {
    peer = new FakeSmtpPeer(serverTls());
    fixture.dns.put("remote.test/MX", List.of("10 127.0.0.1"));
    fixture.dns.put("_mta-sts.remote.test/TXT", List.of("v=STSv1; id=1"));
    fixture.policies.put(
        "remote.test", "version: STSv1\nmode: enforce\nmx: *.remote.test\nmax_age: 86400\n");
    QueueItem item = enqueue("bob@remote.test");
    try (OutboundDelivery delivery = fixture.delivery(fixture.queue, peer().port(), trusting())) {
      delivery.runDueNow();
    }
    assertThat(peer().connections.get()).isZero();
    assertThat(fixture.queue.get(item.id()).orElseThrow().pending().getFirst().lastReply())
        .isEqualTo("mta-sts-no-valid-mx");
  }
}
