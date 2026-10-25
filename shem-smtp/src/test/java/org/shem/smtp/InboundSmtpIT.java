package org.shem.smtp;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.shem.store.PlaintextScan;

@SuppressWarnings(
    "StringConcatToTextBlock") // explicit CRLF line endings read better as concatenation
class InboundSmtpIT {
  private static final String MARKER = "INBOUND-SMTP-MARKER";
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

  private static String message(String subject, String body) {
    return "From: Bob <bob@example.net>\r\nTo: alice@example.org\r\nSubject: "
        + subject
        + "\r\nMessage-ID: <"
        + subject.hashCode()
        + "@example.net>\r\n\r\n"
        + body
        + "\r\n";
  }

  private static String text(byte[] message) {
    return new String(message, StandardCharsets.UTF_8);
  }

  private SmtpClient greeted() throws Exception {
    SmtpClient client = fixture.connect();
    assertThat(client.last()).startsWith("220 ");
    return client;
  }

  @Test
  void deliversToALockedMailboxOnlyAfterDurableCommit() throws Exception {
    try (SmtpClient client = greeted()) {
      client.send("EHLO mx.example.net\r\n");
      List<String> ehlo = client.reply();
      assertThat(ehlo).anyMatch(l -> l.contains("STARTTLS"));
      assertThat(ehlo).anyMatch(l -> l.contains("SIZE " + SmtpFixture.MAX_MESSAGE));
      assertThat(ehlo).anyMatch(l -> l.contains("PIPELINING"));
      assertThat(ehlo).noneMatch(l -> l.contains("AUTH"));
      String reply =
          client.send(
              "bob@example.net",
              List.of(SmtpFixture.ALICE),
              message("Hello " + MARKER, ".leading dot\r\nbody " + MARKER));
      assertThat(reply).startsWith("250 2.6.0");
      assertThat(client.command("QUIT")).startsWith("221");
    }
    assertThat(fixture.smtp.metrics().accepted()).isEqualTo(1);
    PlaintextScan.assertNoMarkers(dir, MARKER, "bob@example.net");
    // Account addresses are routing data (identity); they must not appear in mailbox storage.
    PlaintextScan.assertNoMarkers(dir.resolve("mailboxes"), "alice@example.org");

    List<byte[]> inbox = fixture.aliceInbox();
    assertThat(inbox).hasSize(1);
    String delivered = text(inbox.getFirst());
    assertThat(delivered).startsWith("Authentication-Results: localhost;");
    assertThat(delivered)
        .contains("\r\nReturn-Path: <bob@example.net>\r\nReceived: from mx.example.net ([");
    assertThat(delivered).contains("by localhost (Shem) with ESMTP;");
    assertThat(delivered).contains("\r\n\r\n.leading dot\r\nbody " + MARKER + "\r\n");
    assertThat(delivered).doesNotContain("for <");
  }

  @Test
  void neverRelays() throws Exception {
    try (SmtpClient client = greeted()) {
      client.command("EHLO mx.example.net");
      assertThat(client.command("MAIL FROM:<alice@example.org>")).startsWith("250");
      assertThat(client.command("RCPT TO:<victim@example.net>")).startsWith("550 5.7.1");
      assertThat(client.command("RCPT TO:<alice@example.org.example.net>")).startsWith("550 5.7.1");
      assertThat(client.command("DATA")).startsWith("503");
      client.send("STARTTLS\r\n");
      assertThat(client.last()).startsWith("220");
      client.startTls();
      client.command("EHLO mx.example.net");
      assertThat(client.command("MAIL FROM:<alice@example.org>")).startsWith("250");
      assertThat(client.command("RCPT TO:<victim@example.net>")).startsWith("550 5.7.1");
    }
    assertThat(fixture.smtp.metrics().relayDenied()).isEqualTo(3);
    assertThat(fixture.smtp.metrics().accepted()).isZero();
  }

  @Test
  void unknownRecipientsGetOneResponseAndRepeatedProbingDisconnects() throws Exception {
    try (SmtpClient client = greeted()) {
      client.command("EHLO mx.example.net");
      assertThat(client.command("MAIL FROM:<>")).startsWith("250");
      String first = client.command("RCPT TO:<nobody@example.org>");
      String second = client.command("RCPT TO:<other@example.org>");
      assertThat(first).startsWith("550 5.1.1").isEqualTo(second);
      assertThat(client.command("RCPT TO:<third@example.org>")).isEqualTo(first);
      assertThat(client.command("RCPT TO:<fourth@example.org>")).startsWith("421");
      assertThat(client.last()).isEqualTo("EOF");
    }
  }

  @Test
  void aliasAndDuplicateRecipientsDeliverOncePerMailbox() throws Exception {
    try (SmtpClient client = greeted()) {
      client.command("EHLO mx.example.net");
      String reply =
          client.send(
              "bob@example.net",
              List.of("team@example.org", SmtpFixture.ALICE, "ALICE@Example.ORG"),
              message("team", "to everyone"));
      assertThat(reply).startsWith("250");
    }
    assertThat(fixture.aliceInbox()).hasSize(1);
  }

  @Test
  void recipientLimitIsTemporary() throws Exception {
    try (SmtpClient client = greeted()) {
      client.command("EHLO mx.example.net");
      client.command("MAIL FROM:<bob@example.net>");
      for (int i = 0; i < 5; i++) {
        assertThat(client.command("RCPT TO:<alice@example.org>")).startsWith("250");
      }
      assertThat(client.command("RCPT TO:<alice@example.org>")).startsWith("452 4.5.3");
    }
  }

  @Test
  void oversizedMessagesAreRejectedWithoutDelivery() throws Exception {
    try (SmtpClient client = greeted()) {
      client.command("EHLO mx.example.net");
      assertThat(
              client.command("MAIL FROM:<bob@example.net> SIZE=" + (SmtpFixture.MAX_MESSAGE + 1)))
          .startsWith("552 5.3.4");
      assertThat(client.command("MAIL FROM:<bob@example.net> SIZE=99999999999999"))
          .startsWith("552");
      assertThat(client.command("MAIL FROM:<bob@example.net> SIZE=abc")).startsWith("501");
      assertThat(client.command("MAIL FROM:<bob@example.net> SIZE=100")).startsWith("250");
      assertThat(client.command("RSET")).startsWith("250");
      String big = "x".repeat(998) + "\r\n";
      String reply =
          client.send(
              "bob@example.net",
              List.of(SmtpFixture.ALICE),
              message("big", big.repeat((int) (SmtpFixture.MAX_MESSAGE / big.length()) + 2)));
      assertThat(reply).startsWith("552 5.3.4");
      // The connection stays usable for a following transaction.
      assertThat(client.send("bob@example.net", List.of(SmtpFixture.ALICE), message("small", "ok")))
          .startsWith("250");
    }
    assertThat(fixture.aliceInbox()).hasSize(1);
    assertSpoolEmpty();
  }

  @Test
  void largeMessagesSpoolOnlyCiphertextAndNeverUseTempFiles() throws Exception {
    Path tmp = Path.of(System.getProperty("java.io.tmpdir"));
    Files.createDirectories(tmp);
    List<Path> before;
    try (Stream<Path> files = Files.list(tmp)) {
      before = files.toList();
    }
    String line = MARKER + " " + "y".repeat(200) + "\r\n";
    String body = line.repeat(2000);
    try (SmtpClient client = greeted()) {
      client.command("EHLO mx.example.net");
      client.command("MAIL FROM:<bob@example.net>");
      client.command("RCPT TO:<alice@example.org>");
      assertThat(client.command("DATA")).startsWith("354");
      client.send(message("spooled", body).substring(0, 300_000));
      // Mid-DATA the spool holds data, and only ciphertext.
      awaitSpoolNonEmpty();
      PlaintextScan.assertNoMarkers(fixture.spool, MARKER);
      client.send(message("spooled", body).substring(300_000));
      assertThat(client.command(".")).startsWith("250");
    }
    assertThat(fixture.smtp.metrics().spooled()).isEqualTo(1);
    assertSpoolEmpty();
    try (Stream<Path> files = Files.list(tmp)) {
      assertThat(files.toList()).containsExactlyInAnyOrderElementsOf(before);
    }
    PlaintextScan.assertNoMarkers(dir, MARKER);
    assertThat(text(fixture.aliceInbox().getFirst())).contains(body);
  }

  @Test
  void disconnectDuringDataDeliversNothingAndWipesTheSpool() throws Exception {
    try (SmtpClient client = greeted()) {
      client.command("EHLO mx.example.net");
      client.command("MAIL FROM:<bob@example.net>");
      client.command("RCPT TO:<alice@example.org>");
      client.command("DATA");
      client.send(message("cut", ("z".repeat(500) + "\r\n").repeat(400)));
      awaitSpoolNonEmpty();
    }
    awaitSpoolEmpty();
    assertThat(fixture.aliceInbox()).isEmpty();
  }

  @Test
  void storageFailureIsATemporaryRejection() throws Exception {
    fixture.diskFull = true;
    try (SmtpClient client = greeted()) {
      client.command("EHLO mx.example.net");
      assertThat(client.send("bob@example.net", List.of(SmtpFixture.ALICE), message("full", "x")))
          .startsWith("451 4.3.0");
      fixture.diskFull = false;
      assertThat(client.send("bob@example.net", List.of(SmtpFixture.ALICE), message("ok", "x")))
          .startsWith("250");
    }
    assertThat(fixture.aliceInbox()).hasSize(1);
    assertSpoolEmpty();
  }

  @Test
  void starttlsCommandInjectionIsRefused() throws Exception {
    try (SmtpClient client = greeted()) {
      client.command("EHLO mx.example.net");
      client.send("STARTTLS\r\nMAIL FROM:<bob@example.net>\r\n");
      List<String> reply = client.reply();
      assertThat(reply).noneMatch(l -> l.startsWith("220"));
      while (!client.reply().isEmpty()) {
        // drain until the server closes the connection
      }
    }
  }

  @Test
  void overlongLinesCloseTheConnection() throws Exception {
    try (SmtpClient client = greeted()) {
      client.command("EHLO mx.example.net");
      client.command("MAIL FROM:<bob@example.net>");
      client.command("RCPT TO:<alice@example.org>");
      client.command("DATA");
      client.send(
          "Subject: long\r\n\r\n" + "w".repeat(InboundSmtpRole.MAX_LINE_BYTES + 10) + "\r\n.\r\n");
      assertThat(client.last()).startsWith("500 5.5.2");
      assertThat(client.last()).isEqualTo("EOF");
    }
    awaitSpoolEmpty();
    assertThat(fixture.aliceInbox()).isEmpty();
  }

  @Test
  void pipelinedTransactionIsAnsweredInOrder() throws Exception {
    try (SmtpClient client = greeted()) {
      client.command("EHLO mx.example.net");
      client.send(
          "MAIL FROM:<bob@example.net>\r\nRCPT TO:<alice@example.org>\r\nRCPT TO:<x@example.net>\r\nDATA\r\n");
      assertThat(client.last()).startsWith("250");
      assertThat(client.last()).startsWith("250");
      assertThat(client.last()).startsWith("550");
      assertThat(client.last()).startsWith("354");
      client.send(message("pipelined", "p") + ".\r\nQUIT\r\n");
      assertThat(client.last()).startsWith("250");
      assertThat(client.last()).startsWith("221");
    }
    assertThat(fixture.aliceInbox()).hasSize(1);
  }

  @Test
  void policyResultsAreRecordedAndForgedResultsRemoved() throws Exception {
    fixture.dns.put("example.net/TXT", List.of("v=spf1 ip4:127.0.0.0/8 -all"));
    String forged =
        "Authentication-Results: localhost; spf=pass smtp.mailfrom=forged.example\r\n"
            + "X-Spam-Flag: NO\r\n"
            + message("forged", "body");
    try (SmtpClient client = greeted()) {
      client.command("EHLO mx.example.net");
      assertThat(client.send("bob@example.net", List.of(SmtpFixture.ALICE), forged))
          .startsWith("250");
    }
    String delivered = text(fixture.aliceInbox().getFirst());
    assertThat(delivered).startsWith("Authentication-Results: localhost;");
    assertThat(delivered).contains("spf=pass smtp.mailfrom=example.net");
    assertThat(delivered).doesNotContain("forged.example");
    assertThat(delivered.indexOf("X-Spam-Flag:")).isEqualTo(delivered.lastIndexOf("X-Spam-Flag:"));
    assertThat(delivered).contains("X-Spam-Flag: NO");
  }

  @Test
  void spamIsDeliveredToJunkNotRejected() throws Exception {
    String gtube = "XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X";
    try (SmtpClient client = greeted()) {
      client.command("EHLO mx.example.net");
      assertThat(client.send("bob@example.net", List.of(SmtpFixture.ALICE), message("spam", gtube)))
          .startsWith("250");
    }
    assertThat(fixture.aliceInbox()).isEmpty();
    List<byte[]> junk = fixture.aliceFolder(org.shem.store.SpecialUse.JUNK);
    assertThat(junk).hasSize(1);
    assertThat(text(junk.getFirst())).contains("X-Spam-Flag: YES");
    assertThat(fixture.smtp.metrics().junk()).isEqualTo(1);
  }

  @Test
  void dmarcRejectAndDangerousAttachmentsAreRefusedBeforeDelivery() throws Exception {
    fixture.dns.put("_dmarc.bank.example/TXT", List.of("v=DMARC1; p=reject"));
    String spoofed =
        "From: Bank <alerts@bank.example>\r\nTo: alice@example.org\r\nSubject: verify\r\n\r\nclick\r\n";
    String attachment =
        "From: bob@example.net\r\nSubject: invoice\r\nMIME-Version: 1.0\r\n"
            + "Content-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\n"
            + "see attached\r\n--B\r\nContent-Type: application/octet-stream\r\n"
            + "Content-Disposition: attachment; filename=\"invoice.pdf.exe\"\r\n\r\nTVo=\r\n--B--\r\n";
    try (SmtpClient client = greeted()) {
      client.command("EHLO mx.example.net");
      assertThat(client.send("phisher@elsewhere.example", List.of(SmtpFixture.ALICE), spoofed))
          .startsWith("550 5.7.1");
      assertThat(client.send("bob@example.net", List.of(SmtpFixture.ALICE), attachment))
          .startsWith("550 5.7.1");
    }
    assertThat(fixture.aliceInbox()).isEmpty();
    assertThat(fixture.smtp.metrics().policyRejected()).isEqualTo(2);
    assertSpoolEmpty();
  }

  @Test
  void greylistingDefersTheFirstAttemptOnly(@TempDir Path other) throws Exception {
    try (SmtpFixture greylisted =
        new SmtpFixture(
            other,
            new org.shem.policy.Greylist.Settings(
                java.time.Duration.ZERO,
                java.time.Duration.ofHours(4),
                java.time.Duration.ofDays(35),
                1000))) {
      try (SmtpClient client = greylisted.connect()) {
        client.last();
        client.command("EHLO mx.example.net");
        client.command("MAIL FROM:<bob@example.net>");
        assertThat(client.command("RCPT TO:<alice@example.org>")).startsWith("451 4.7.1");
        assertThat(client.command("RCPT TO:<nobody@example.org>")).startsWith("550 5.1.1");
        client.command("RSET");
        assertThat(
                client.send("bob@example.net", List.of(SmtpFixture.ALICE), message("retry", "x")))
            .startsWith("250");
      }
      assertThat(greylisted.smtp.metrics().greylisted()).isEqualTo(1);
      assertThat(greylisted.aliceInbox()).hasSize(1);
    }
  }

  private long spoolFiles() throws Exception {
    if (!Files.exists(fixture.spool)) {
      return 0;
    }
    try (Stream<Path> files = Files.list(fixture.spool)) {
      return files.count();
    }
  }

  private void assertSpoolEmpty() throws Exception {
    assertThat(spoolFiles()).isZero();
  }

  private void awaitSpoolNonEmpty() throws Exception {
    await(true);
  }

  private void awaitSpoolEmpty() throws Exception {
    await(false);
  }

  /** Waits for asynchronous server-side progress; bounded, fails rather than hangs. */
  private void await(boolean nonEmpty) throws Exception {
    long deadline = System.nanoTime() + 10_000_000_000L;
    while ((spoolFiles() > 0) != nonEmpty) {
      assertThat(System.nanoTime()).as("spool state").isLessThan(deadline);
      Thread.sleep(10);
    }
  }
}
