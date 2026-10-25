package org.shem.smtp;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

@SuppressWarnings(
    "StringConcatToTextBlock") // explicit CRLF line endings read better as concatenation
class SubmissionIT {
  @TempDir Path dir;
  private SmtpFixture fixture;

  @BeforeEach
  void setUp() throws Exception {
    fixture = new SmtpFixture(dir);
  }

  @AfterEach
  void tearDown() {
    fixture.close();
  }

  private static String plain(String user, String password) {
    return Base64.getEncoder()
        .encodeToString(("\0" + user + "\0" + password).getBytes(StandardCharsets.UTF_8));
  }

  private static String b64(String value) {
    return Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8));
  }

  private static String message(String from, String to, String subject) {
    return "From: " + from + "\r\nTo: " + to + "\r\nSubject: " + subject + "\r\n\r\nbody\r\n";
  }

  /** Connects to 587, upgrades with STARTTLS, and authenticates as alice. */
  private SmtpClient authenticated() throws Exception {
    SmtpClient client = fixture.submissionStartTls();
    client.last();
    client.command("EHLO laptop");
    assertThat(client.command("STARTTLS")).startsWith("220");
    client.startTls();
    client.command("EHLO laptop");
    assertThat(client.command("AUTH PLAIN " + plain(SmtpFixture.ALICE, SmtpFixture.PASSWORD)))
        .startsWith("235 2.7.0");
    return client;
  }

  @Test
  void credentialsAreNeverAcceptedBeforeTls() throws Exception {
    try (SmtpClient client = fixture.submissionStartTls()) {
      client.last();
      client.send("EHLO laptop\r\n");
      List<String> ehlo = client.reply();
      assertThat(ehlo).anyMatch(l -> l.contains("STARTTLS"));
      assertThat(ehlo).noneMatch(l -> l.contains("AUTH"));
      assertThat(client.command("AUTH PLAIN " + plain(SmtpFixture.ALICE, SmtpFixture.PASSWORD)))
          .startsWith("538 5.7.11");
      assertThat(client.command("MAIL FROM:<alice@example.org>")).startsWith("530 5.7.0");
      assertThat(client.command("STARTTLS")).startsWith("220");
      client.startTls();
      client.send("EHLO laptop\r\n");
      assertThat(client.reply()).anyMatch(l -> l.contains("AUTH PLAIN LOGIN"));
      assertThat(client.command("MAIL FROM:<alice@example.org>")).startsWith("530 5.7.0");
    }
  }

  @Test
  void wrongCredentialsFailAndRepeatedFailuresDisconnect() throws Exception {
    try (SmtpClient client = fixture.submissionImplicitTls()) {
      client.last();
      client.command("EHLO laptop");
      assertThat(client.command("AUTH PLAIN " + plain(SmtpFixture.ALICE, "wrong")))
          .startsWith("535");
      assertThat(client.command("AUTH PLAIN " + plain("nobody@example.org", "wrong")))
          .startsWith("535");
      assertThat(
              client.command(
                  "AUTH PLAIN "
                      + Base64.getEncoder()
                          .encodeToString(
                              ("carol@example.org\0"
                                      + SmtpFixture.ALICE
                                      + "\0"
                                      + SmtpFixture.PASSWORD)
                                  .getBytes(StandardCharsets.UTF_8))))
          .as("authorization identity must match")
          .startsWith("421");
      assertThat(client.last()).isEqualTo("EOF");
    }
  }

  @Test
  void authenticatedUsersSendToLocalRecipients() throws Exception {
    try (SmtpClient client = authenticated()) {
      assertThat(
              client.send(
                  SmtpFixture.ALICE,
                  List.of(SmtpFixture.ALICE, SmtpFixture.CAROL),
                  message("Alice <alice@example.org>", "carol@example.org", "local")))
          .startsWith("250 2.6.0");
    }
    String delivered = new String(fixture.aliceInbox().getFirst(), StandardCharsets.UTF_8);
    assertThat(delivered).startsWith("DKIM-Signature: ");
    assertThat(delivered)
        .contains(
            "\r\nReturn-Path: <alice@example.org>\r\nReceived: by localhost (Shem) with ESMTPSA;");
    assertThat(delivered).as("the user's address is not disclosed").doesNotContain("127.0.0.1");
  }

  @Test
  void loginMechanismOnImplicitTls() throws Exception {
    try (SmtpClient client = fixture.submissionImplicitTls()) {
      assertThat(client.last()).startsWith("220");
      client.command("EHLO laptop");
      assertThat(client.command("AUTH LOGIN")).startsWith("334 VXNlcm5hbWU6");
      assertThat(client.command(b64(SmtpFixture.ALICE))).startsWith("334 UGFzc3dvcmQ6");
      assertThat(client.command(b64(SmtpFixture.PASSWORD))).startsWith("235");
      assertThat(
              client.send(
                  SmtpFixture.ALICE,
                  List.of(SmtpFixture.ALICE),
                  message(SmtpFixture.ALICE, SmtpFixture.ALICE, "login")))
          .startsWith("250");
    }
    assertThat(fixture.aliceInbox()).hasSize(1);
  }

  @Test
  void sendersCannotImpersonateOthers() throws Exception {
    try (SmtpClient client = authenticated()) {
      assertThat(client.command("MAIL FROM:<carol@example.org>")).startsWith("553 5.7.1");
      assertThat(client.command("MAIL FROM:<bob@example.net>")).startsWith("553 5.7.1");
      assertThat(client.command("MAIL FROM:<>")).startsWith("553 5.7.1");
      assertThat(
              client.send(
                  SmtpFixture.ALICE,
                  List.of(SmtpFixture.ALICE),
                  message("CEO <carol@example.org>", SmtpFixture.ALICE, "spoof")))
          .startsWith("554 5.7.1");
      assertThat(
              client.send(
                  SmtpFixture.ALICE,
                  List.of(SmtpFixture.ALICE),
                  "To: alice@example.org\r\nSubject: none\r\n\r\nno from\r\n"))
          .startsWith("554 5.6.0");
      assertThat(
              client.send(
                  "sales@example.org",
                  List.of(SmtpFixture.ALICE),
                  message("Sales <sales@example.org>", SmtpFixture.ALICE, "alias")))
          .as("an alias the account may send as")
          .startsWith("250");
    }
    assertThat(fixture.aliceInbox()).hasSize(1);
  }

  @Test
  void remoteRecipientsAreSignedAndQueuedBeforeAcceptance() throws Exception {
    try (SmtpClient client = authenticated()) {
      client.command("MAIL FROM:<alice@example.org>");
      assertThat(client.command("RCPT TO:<nobody@example.org>")).startsWith("550 5.1.1");
      client.command("RSET");
      assertThat(
              client.send(
                  SmtpFixture.ALICE,
                  List.of("friend@example.net", SmtpFixture.ALICE),
                  message("Alice <alice@example.org>", "friend@example.net", "remote")))
          .startsWith("250");
    }
    assertThat(fixture.queue.size()).isEqualTo(1);
    org.shem.outbound.QueueItem item =
        fixture.queue.due(java.time.Instant.now().plusSeconds(1)).getFirst();
    assertThat(item.sender()).isEqualTo(SmtpFixture.ALICE);
    assertThat(item.recipients())
        .extracting(org.shem.outbound.QueueItem.Recipient::address)
        .containsExactly("friend@example.net");
    byte[] queued;
    try (var in = fixture.queue.openMessage(item.id())) {
      queued = in.readAllBytes();
    }
    assertThat(new String(queued, StandardCharsets.UTF_8)).startsWith("DKIM-Signature:");
    org.apache.james.jdkim.DKIMVerifier verifier =
        new org.apache.james.jdkim.DKIMVerifier((m, sel, d) -> List.of(fixture.dkimRecord));
    assertThat(verifier.verify(new java.io.ByteArrayInputStream(queued)))
        .as("the queued bytes are exactly the signed bytes")
        .hasSize(1);
    byte[] local = fixture.aliceInbox().getFirst();
    assertThat(
            new org.apache.james.jdkim.DKIMVerifier((m, sel, d) -> List.of(fixture.dkimRecord))
                .verify(new java.io.ByteArrayInputStream(local)))
        .as("the local copy carries a valid signature too")
        .hasSize(1);
  }

  @Test
  void allLocalMailNeverTouchesTheQueueAndAFullQueueIsTemporary() throws Exception {
    try (SmtpClient client = authenticated()) {
      assertThat(
              client.send(
                  SmtpFixture.ALICE,
                  List.of(SmtpFixture.ALICE),
                  message(SmtpFixture.ALICE, SmtpFixture.ALICE, "local")))
          .startsWith("250");
      assertThat(fixture.queue.size()).isZero();
      for (int i = 0; i < 3; i++) {
        assertThat(
                client.send(
                    SmtpFixture.ALICE,
                    List.of("x" + i + "@example.net"),
                    message(SmtpFixture.ALICE, "x@example.net", "q" + i)))
            .startsWith("250");
      }
      client.command("RSET");
      assertThat(
              client.send(
                  SmtpFixture.ALICE,
                  List.of("y@example.net", SmtpFixture.ALICE),
                  message(SmtpFixture.ALICE, "y@example.net", "full")))
          .startsWith("452 4.3.1");
    }
    assertThat(fixture.aliceInbox())
        .as("nothing committed locally when the queue refused")
        .hasSize(1);
  }

  @Test
  void recipientRateIsLimitedPerAccount() throws Exception {
    try (SmtpClient client = authenticated()) {
      for (int round = 0; round < 2; round++) {
        client.command("MAIL FROM:<alice@example.org>");
        for (int i = 0; i < 4; i++) {
          assertThat(client.command("RCPT TO:<alice@example.org>")).startsWith("250");
        }
        client.command("RSET");
      }
      client.command("MAIL FROM:<alice@example.org>");
      assertThat(client.command("RCPT TO:<alice@example.org>")).startsWith("451 4.7.0");
    }
  }

  @Test
  void revokedSessionsLoseAuthorizationImmediately() throws Exception {
    try (SmtpClient client = authenticated()) {
      fixture.registry.revokeMailbox(
          fixture.identity.loginAccount(SmtpFixture.ALICE).orElseThrow().mailboxId());
      assertThat(client.command("MAIL FROM:<alice@example.org>")).startsWith("421 4.7.0");
      assertThat(client.last()).isEqualTo("EOF");
    }
  }

  @Test
  void jakartaMailClientSubmitsOverStartTls() throws Exception {
    java.util.Properties props = new java.util.Properties();
    props.put("mail.smtp.host", "127.0.0.1");
    props.put("mail.smtp.port", String.valueOf(fixture.submission.startTlsPort()));
    props.put("mail.smtp.auth", "true");
    props.put("mail.smtp.starttls.enable", "true");
    props.put("mail.smtp.starttls.required", "true");
    props.put(
        "mail.smtp.ssl.socketFactory",
        org.shem.tls.TestCertificates.clientTrusting(fixture.certificate.certificate())
            .getSocketFactory());
    props.put("mail.smtp.ssl.checkserveridentity", "false");
    props.put("mail.smtp.connectiontimeout", "10000");
    props.put("mail.smtp.timeout", "20000");
    jakarta.mail.Session session = jakarta.mail.Session.getInstance(props);
    jakarta.mail.internet.MimeMessage message = new jakarta.mail.internet.MimeMessage(session);
    message.setFrom(new jakarta.mail.internet.InternetAddress(SmtpFixture.ALICE));
    message.setRecipients(jakarta.mail.Message.RecipientType.TO, SmtpFixture.ALICE);
    message.setSubject("from a real client");
    message.setText("hello from jakarta mail");
    try (jakarta.mail.Transport transport = session.getTransport("smtp")) {
      transport.connect(SmtpFixture.ALICE, SmtpFixture.PASSWORD);
      transport.sendMessage(message, message.getAllRecipients());
    }
    String delivered = new String(fixture.aliceInbox().getFirst(), StandardCharsets.UTF_8);
    assertThat(delivered)
        .contains("Subject: from a real client")
        .contains("hello from jakarta mail");
  }
}
