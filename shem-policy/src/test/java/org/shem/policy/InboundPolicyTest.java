package org.shem.policy;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.InetAddress;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

@SuppressWarnings(
    "StringConcatToTextBlock") // explicit CRLF line endings read better as concatenation
class InboundPolicyTest {
  private static KeyPair keys;
  private static InetAddress client;

  @BeforeAll
  static void setUp() throws Exception {
    keys = Fixtures.rsa();
    client = InetAddress.getByName("198.51.100.7");
  }

  private static FakeDns dns() {
    return new FakeDns()
        .add("example.net", DnsResolver.Type.TXT, "v=spf1 ip4:198.51.100.0/24 -all")
        .add("_dmarc.example.net", DnsResolver.Type.TXT, "v=DMARC1; p=reject")
        .add("s1._domainkey.example.net", DnsResolver.Type.TXT, Fixtures.keyRecord(keys))
        .add("_dmarc.lenient.example", DnsResolver.Type.TXT, "v=DMARC1; p=quarantine");
  }

  private static InboundPolicy policy(FakeDns dns, InboundPolicy.Enforcement attachments) {
    return new InboundPolicy(
        new InboundPolicy.Settings(
            "mx.shem.test", 5.0, InboundPolicy.Enforcement.REJECT, attachments, List.of()),
        dns,
        new SecureRandom());
  }

  private static InboundPolicy.Verdict evaluate(
      InboundPolicy policy, String ip, String from, String message) throws Exception {
    return policy.evaluate(
        new InboundPolicy.Envelope(InetAddress.getByName(ip), "mx.example.net", from),
        Fixtures.input(message));
  }

  @Test
  void authenticatedMailIsDeliveredWithAuthenticationResults() throws Exception {
    String signed =
        Fixtures.sign(Fixtures.message("bob@example.net", "hello"), "example.net", keys);
    InboundPolicy.Verdict verdict =
        evaluate(
            policy(dns(), InboundPolicy.Enforcement.REJECT),
            "198.51.100.7",
            "bob@example.net",
            signed);
    assertThat(verdict.action()).isEqualTo(InboundPolicy.Action.DELIVER);
    assertThat(verdict.fields().getFirst())
        .startsWith("Authentication-Results: mx.shem.test;")
        .contains("spf=pass smtp.mailfrom=example.net")
        .contains("dkim=pass header.d=example.net header.s=s1")
        .contains("dmarc=pass (p=reject) header.from=example.net");
    assertThat(verdict.fields()).contains("X-Spam-Flag: NO");
  }

  @Test
  void spoofedDomainWithRejectPolicyIsRejected() throws Exception {
    InboundPolicy.Verdict verdict =
        evaluate(
            policy(dns(), InboundPolicy.Enforcement.REJECT),
            "203.0.113.9",
            "bob@example.net",
            Fixtures.message("ceo@example.net", "wire the money"));
    assertThat(verdict.action()).isEqualTo(InboundPolicy.Action.REJECT);
    assertThat(verdict.reply()).startsWith("550 5.7.1");
    assertThat(verdict.tags()).contains("dmarc-fail");
  }

  @Test
  void quarantinePolicyAndGtubeRouteToJunk() throws Exception {
    InboundPolicy policy = policy(dns(), InboundPolicy.Enforcement.REJECT);
    assertThat(
            evaluate(
                    policy,
                    "203.0.113.9",
                    "x@lenient.example",
                    Fixtures.message("x@lenient.example", "hi"))
                .action())
        .isEqualTo(InboundPolicy.Action.JUNK);
    InboundPolicy.Verdict gtube =
        evaluate(
            policy,
            "198.51.100.7",
            "bob@example.net",
            Fixtures.sign(
                Fixtures.message("bob@example.net", InboundPolicy.GTUBE), "example.net", keys));
    assertThat(gtube.action()).isEqualTo(InboundPolicy.Action.JUNK);
    assertThat(gtube.tags()).contains("spam");
    assertThat(gtube.fields()).contains("X-Spam-Flag: YES");
    assertThat(String.join("\n", gtube.fields())).contains("tests=GTUBE");
  }

  @Test
  void temporaryDnsFailuresNeverTurnIntoRejection() throws Exception {
    FakeDns dns = dns().fail("_dmarc.flaky.example");
    assertThat(
            evaluate(
                    policy(dns, InboundPolicy.Enforcement.REJECT),
                    "203.0.113.9",
                    "a@flaky.example",
                    Fixtures.message("a@flaky.example", "x"))
                .action())
        .isEqualTo(InboundPolicy.Action.TEMPFAIL);
    FakeDns spfDown = dns().fail("example.net");
    InboundPolicy.Verdict verdict =
        evaluate(
            policy(spfDown, InboundPolicy.Enforcement.REJECT),
            "203.0.113.9",
            "bob@example.net",
            Fixtures.message("bob@example.net", "x"));
    assertThat(verdict.action()).isEqualTo(InboundPolicy.Action.TEMPFAIL);
    assertThat(verdict.reply()).startsWith("451");
  }

  @Test
  void dangerousAttachmentsFollowTheirExplicitSetting() throws Exception {
    String message =
        Fixtures.message("bob@example.net", "see attached")
            .replace(
                "Content-Type: text/plain; charset=utf-8\r\n\r\nsee attached\r\n",
                "Content-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\n"
                    + "see attached\r\n--B\r\nContent-Type: application/octet-stream\r\n"
                    + "Content-Disposition: attachment; filename=\"invoice.pdf.exe\"\r\n\r\nMZ\r\n--B--\r\n");
    String signed = Fixtures.sign(message, "example.net", keys);
    InboundPolicy.Verdict rejected =
        evaluate(
            policy(dns(), InboundPolicy.Enforcement.REJECT),
            "198.51.100.7",
            "bob@example.net",
            signed);
    assertThat(rejected.action()).isEqualTo(InboundPolicy.Action.REJECT);
    InboundPolicy.Verdict junked =
        evaluate(
            policy(dns(), InboundPolicy.Enforcement.JUNK),
            "198.51.100.7",
            "bob@example.net",
            signed);
    assertThat(junked.action()).isEqualTo(InboundPolicy.Action.JUNK);
    assertThat(junked.fields()).contains("X-Shem-Attachment: double-extension");
  }

  @Test
  void contentRulesAreReplacedAtomically() throws Exception {
    InboundPolicy policy = policy(dns(), InboundPolicy.Enforcement.REJECT);
    String signed =
        Fixtures.sign(Fixtures.message("bob@example.net", "buy cheap pills"), "example.net", keys);
    assertThat(evaluate(policy, "198.51.100.7", "bob@example.net", signed).action())
        .isEqualTo(InboundPolicy.Action.DELIVER);
    policy.replaceRules(RuleSet.parse(List.of("PILLS body \"cheap pills\" 6")));
    assertThat(evaluate(policy, "198.51.100.7", "bob@example.net", signed).action())
        .isEqualTo(InboundPolicy.Action.JUNK);
  }

  @Test
  void headerInjectionThroughSenderValuesIsNeutralized() throws Exception {
    InboundPolicy.Verdict verdict =
        evaluate(
            policy(dns(), InboundPolicy.Enforcement.REJECT),
            "198.51.100.7",
            "",
            Fixtures.message("bob@example.net", "x"));
    assertThat(String.join("\n", verdict.fields())).doesNotContain("\r\n\r\n");
    assertThat(InboundPolicy.reversed(client)).isEqualTo("7.100.51.198");
    assertThat(InboundPolicy.reversed(InetAddress.getByName("2001:db8::1")))
        .startsWith("1.0.0.0.")
        .endsWith(".8.b.d.0.1.0.0.2");
  }
}
