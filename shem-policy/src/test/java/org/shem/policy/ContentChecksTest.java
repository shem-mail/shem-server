package org.shem.policy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayInputStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

@SuppressWarnings(
    "StringConcatToTextBlock") // explicit CRLF line endings read better as concatenation
class ContentChecksTest {
  @Test
  void rulesParseValidateAndMatchLiterally() throws Exception {
    RuleSet rules =
        RuleSet.parse(
            List.of(
                "# comment",
                "",
                "CHEAP_PILLS body \"cheap pills\" 3.5",
                "BAD_SUBJECT header \"subject: win\" 2",
                "REGEX_IS_LITERAL any \"(a+)+$\" 1",
                "NICE any \"newsletter\" -1"));
    assertThat(rules.size()).isEqualTo(4);
    List<String> hits = new ArrayList<>();
    double score = rules.apply("SUBJECT: WIN BIG\n", "BUY CHEAP PILLS (A+)+$ NOW", hits);
    assertThat(hits).containsExactly("CHEAP_PILLS", "BAD_SUBJECT", "REGEX_IS_LITERAL");
    assertThat(score).isEqualTo(6.5);

    assertThatThrownBy(() -> RuleSet.parse(List.of("lower body \"abc\" 1")))
        .hasMessageContaining("line 1");
    assertThatThrownBy(() -> RuleSet.parse(List.of("A body \"ab\" 1")))
        .hasMessageContaining("3 to");
    assertThatThrownBy(() -> RuleSet.parse(List.of("A body \"abc\" 101")))
        .hasMessageContaining("score");
    assertThatThrownBy(() -> RuleSet.parse(List.of("A body \"abc\" 1", "A body \"abd\" 1")))
        .hasMessageContaining("duplicate");
  }

  @Test
  void rulesMatchingIsLinearForAdversarialInput() throws Exception {
    RuleSet rules = RuleSet.parse(List.of("A body \"" + "a".repeat(199) + "b\" 1"));
    String text = "A".repeat(MessageScan.MAX_TEXT_CHARS);
    long start = System.nanoTime();
    rules.apply("", text, new ArrayList<>());
    assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofSeconds(5));
  }

  private static final class MutableClock extends Clock {
    Instant now = Instant.parse("2026-10-25T10:00:00Z");

    @Override
    public ZoneOffset getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(java.time.ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      return now;
    }
  }

  @Test
  void greylistDefersFirstAttemptsAndRemembersPassedTriplets() throws Exception {
    MutableClock clock = new MutableClock();
    Greylist greylist =
        new Greylist(
            new Greylist.Settings(
                Duration.ofMinutes(5), Duration.ofHours(4), Duration.ofDays(35), 3),
            clock,
            new SecureRandom());
    InetAddress client = InetAddress.getByName("198.51.100.7");
    InetAddress neighbour = InetAddress.getByName("198.51.100.99");
    assertThat(greylist.admit(client, "bob@example.net", "alice@example.org")).isFalse();
    clock.now = clock.now.plusSeconds(60);
    assertThat(greylist.admit(client, "bob@example.net", "alice@example.org")).isFalse();
    clock.now = clock.now.plusSeconds(300);
    assertThat(greylist.admit(neighbour, "BOB@example.net", "alice@example.org"))
        .as("same /24, case-insensitive")
        .isTrue();
    clock.now = clock.now.plus(Duration.ofDays(10));
    assertThat(greylist.admit(client, "bob@example.net", "alice@example.org")).isTrue();
    assertThat(greylist.admit(client, "carol@example.net", "alice@example.org")).isFalse();

    clock.now = clock.now.plus(Duration.ofHours(5));
    assertThat(greylist.admit(client, "carol@example.net", "alice@example.org"))
        .as("a retry after the window starts over")
        .isFalse();
    for (int i = 0; i < 10; i++) {
      greylist.admit(client, "s" + i + "@example.net", "alice@example.org");
    }
    assertThat(greylist.size()).isEqualTo(3);
  }

  @Test
  void dangerousAttachmentsAreFound() {
    assertThat(
            AttachmentCheck.findings(
                List.of(
                    new MessageScan.Attachment("report.pdf", "application/pdf"),
                    new MessageScan.Attachment("invoice.pdf.exe", "application/octet-stream"),
                    new MessageScan.Attachment("setup.EXE. ", "application/octet-stream"),
                    new MessageScan.Attachment("budget.xlsm", "application/octet-stream"),
                    new MessageScan.Attachment("", "application/x-msdownload"))))
        .containsExactly(
            "double-extension", "dangerous-extension", "dangerous-extension", "dangerous-type");
  }

  @Test
  void messageScanDecodesTextAndListsAttachments() throws Exception {
    String message =
        "From: a@example.net\r\nSubject: hi\r\nMIME-Version: 1.0\r\n"
            + "Content-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\n"
            + "Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n"
            + java.util.Base64.getMimeEncoder()
                .encodeToString(InboundPolicy.GTUBE.getBytes(StandardCharsets.US_ASCII))
            + "\r\n--B\r\nContent-Type: application/octet-stream; name=\"tool.scr\"\r\n"
            + "Content-Transfer-Encoding: base64\r\n\r\nAAAA\r\n--B--\r\n";
    MessageScan.Result result =
        MessageScan.scan(new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)));
    assertThat(result.bodyText()).contains(InboundPolicy.GTUBE);
    assertThat(result.attachments())
        .containsExactly(new MessageScan.Attachment("tool.scr", "application/octet-stream"));
    assertThat(result.headerText()).contains("Subject: hi");
    assertThat(result.malformed()).isFalse();
  }

  @Test
  void headerRewriteIsByteExactAndSized() throws Exception {
    byte[] original =
        ("Authentication-Results: mx.shem.test; spf=pass\r\n\tsmtp.mailfrom=forged.example\r\n"
                + "Subject: café ÿ\r\n"
                + "authentication-results: other.example; dkim=pass\r\n"
                + "X-Spam-Flag: NO\r\n\r\n"
                + "Authentication-Results: mx.shem.test; in the body stays\r\n")
            .getBytes(StandardCharsets.ISO_8859_1);
    InboundPolicy policy =
        new InboundPolicy(
            new InboundPolicy.Settings(
                "mx.shem.test",
                5,
                InboundPolicy.Enforcement.REJECT,
                InboundPolicy.Enforcement.REJECT,
                List.of()),
            new FakeDns(),
            new SecureRandom());
    HeaderRewriter.Plan plan =
        HeaderRewriter.plan(
            new ByteArrayInputStream(original),
            original.length,
            List.of("X-New: 1"),
            policy::untrusted);
    byte[] rewritten = plan.apply(new ByteArrayInputStream(original)).readAllBytes();
    assertThat(plan.removed()).isEqualTo(2);
    assertThat(rewritten).hasSize((int) plan.size());
    assertThat(new String(rewritten, StandardCharsets.ISO_8859_1))
        .isEqualTo(
            "X-New: 1\r\n"
                + "Subject: café ÿ\r\n"
                + "authentication-results: other.example; dkim=pass\r\n\r\n"
                + "Authentication-Results: mx.shem.test; in the body stays\r\n");
  }

  @Test
  void rulesFileReloadKeepsLastKnownGood(@org.junit.jupiter.api.io.TempDir java.nio.file.Path dir)
      throws Exception {
    java.nio.file.Path file = dir.resolve("rules.txt");
    java.nio.file.Files.writeString(file, "A body \"abc\" 1\n");
    InboundPolicy policy =
        new InboundPolicy(
            new InboundPolicy.Settings(
                "mx.shem.test",
                5,
                InboundPolicy.Enforcement.REJECT,
                InboundPolicy.Enforcement.REJECT,
                List.of()),
            new FakeDns(),
            new SecureRandom());
    RulesFile rules = new RulesFile(file, policy);
    rules.load();
    assertThat(policy.ruleCount()).isEqualTo(1);
    assertThat(rules.reloadIfChanged()).isEqualTo(RulesFile.Reload.UNCHANGED);

    java.nio.file.Files.writeString(file, "A body \"abc\" 1\nbroken line\n");
    java.nio.file.Files.setLastModifiedTime(
        file, java.nio.file.attribute.FileTime.from(Instant.parse("2030-01-01T00:00:00Z")));
    assertThat(rules.reloadIfChanged()).isEqualTo(RulesFile.Reload.REJECTED);
    assertThat(rules.lastError()).contains("line 2");
    assertThat(policy.ruleCount()).as("last known good stays active").isEqualTo(1);

    java.nio.file.Files.writeString(file, "A body \"abc\" 1\nB header \"xyz\" 2\n");
    java.nio.file.Files.setLastModifiedTime(
        file, java.nio.file.attribute.FileTime.from(Instant.parse("2030-01-02T00:00:00Z")));
    assertThat(rules.reloadIfChanged()).isEqualTo(RulesFile.Reload.RELOADED);
    assertThat(policy.ruleCount()).isEqualTo(2);
  }
}
