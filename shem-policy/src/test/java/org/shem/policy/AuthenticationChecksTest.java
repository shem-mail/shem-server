package org.shem.policy;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class AuthenticationChecksTest {
  private static KeyPair keys;

  @BeforeAll
  static void generate() throws Exception {
    keys = Fixtures.rsa();
  }

  private static SpfCheck.Outcome spf(FakeDns dns, String ip, String from) {
    return new SpfCheck(dns).check(ip, from, "mx.example.net");
  }

  @Test
  void spfResults() {
    FakeDns dns =
        new FakeDns()
            .add("example.net", DnsResolver.Type.TXT, "v=spf1 ip4:198.51.100.0/24 -all")
            .add("soft.example", DnsResolver.Type.TXT, "v=spf1 ~all")
            .add("two.example", DnsResolver.Type.TXT, "v=spf1 -all", "v=spf1 +all")
            .fail("broken.example");
    assertThat(spf(dns, "198.51.100.7", "bob@example.net").result()).isEqualTo(AuthResult.PASS);
    assertThat(spf(dns, "203.0.113.9", "bob@example.net").result()).isEqualTo(AuthResult.FAIL);
    assertThat(spf(dns, "203.0.113.9", "bob@soft.example").result()).isEqualTo(AuthResult.SOFTFAIL);
    assertThat(spf(dns, "203.0.113.9", "bob@none.example").result()).isEqualTo(AuthResult.NONE);
    assertThat(spf(dns, "203.0.113.9", "bob@two.example").result()).isEqualTo(AuthResult.PERMERROR);
    assertThat(spf(dns, "203.0.113.9", "bob@broken.example").result())
        .isEqualTo(AuthResult.TEMPERROR);
    SpfCheck.Outcome bounce = spf(dns, "203.0.113.9", "");
    assertThat(bounce.identity()).isEqualTo("helo");
    assertThat(bounce.domain()).isEqualTo("mx.example.net");
  }

  @Test
  void spfLookupLimitIsEnforced() {
    FakeDns dns = new FakeDns();
    for (int i = 0; i < 15; i++) {
      dns.add(
          "l" + i + ".example",
          DnsResolver.Type.TXT,
          "v=spf1 include:l" + (i + 1) + ".example -all");
    }
    assertThat(spf(dns, "203.0.113.9", "bob@l0.example").result()).isEqualTo(AuthResult.PERMERROR);
    assertThat(dns.queries.size()).isLessThan(15);
  }

  private static List<DkimCheck.Outcome> dkim(FakeDns dns, String message) throws Exception {
    try (InputStream in = new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8))) {
      HeaderBlock headers = HeaderBlock.read(in);
      return new DkimCheck(dns).verify(headers, in);
    }
  }

  @Test
  void dkimPassFailAndTemperror() throws Exception {
    FakeDns dns =
        new FakeDns()
            .add("s1._domainkey.example.net", DnsResolver.Type.TXT, Fixtures.keyRecord(keys));
    String signed =
        Fixtures.sign(Fixtures.message("bob@example.net", "hello"), "example.net", keys);
    assertThat(dkim(dns, signed))
        .containsExactly(new DkimCheck.Outcome(AuthResult.PASS, "example.net", "s1"));
    assertThat(dkim(dns, signed.replace("hello", "hellO")).getFirst().result())
        .isEqualTo(AuthResult.FAIL);
    assertThat(dkim(dns, Fixtures.message("bob@example.net", "unsigned"))).isEmpty();
    FakeDns down = new FakeDns().fail("s1._domainkey.example.net");
    assertThat(dkim(down, signed).getFirst().result()).isEqualTo(AuthResult.TEMPERROR);
  }

  @Test
  void dkimSignatureCountIsBounded() throws Exception {
    FakeDns dns = new FakeDns();
    String message = Fixtures.message("bob@example.net", "many");
    for (int i = 0; i < 8; i++) {
      message = Fixtures.sign(message, "d" + i + ".example", keys);
    }
    dkim(dns, message);
    assertThat(dns.queries).hasSize(HeaderBlock.MAX_DKIM_SIGNATURES);
  }

  private static Dmarc.Outcome dmarc(
      FakeDns dns, String from, AuthResult spf, String spfDomain, int sample) {
    return new Dmarc(dns, () -> sample)
        .evaluate(from, new SpfCheck.Outcome(spf, "mailfrom", spfDomain), List.of());
  }

  @Test
  void dmarcAlignmentPolicyAndInheritance() {
    FakeDns dns =
        new FakeDns()
            .add("_dmarc.example.net", DnsResolver.Type.TXT, "v=DMARC1; p=reject; sp=quarantine")
            .add("_dmarc.strict.example", DnsResolver.Type.TXT, "v=DMARC1; p=reject; aspf=s")
            .add("_dmarc.half.example", DnsResolver.Type.TXT, "v=DMARC1; p=reject; pct=50")
            .fail("_dmarc.broken.example");
    assertThat(dmarc(dns, "example.net", AuthResult.PASS, "bounce.example.net", 0).result())
        .isEqualTo(AuthResult.PASS);
    Dmarc.Outcome failed = dmarc(dns, "example.net", AuthResult.FAIL, "example.net", 0);
    assertThat(failed.result()).isEqualTo(AuthResult.FAIL);
    assertThat(failed.disposition()).isEqualTo(Dmarc.Disposition.REJECT);
    assertThat(dmarc(dns, "news.example.net", AuthResult.NONE, "x.example", 0).disposition())
        .as("subdomain policy from the organizational domain")
        .isEqualTo(Dmarc.Disposition.QUARANTINE);
    assertThat(dmarc(dns, "strict.example", AuthResult.PASS, "mail.strict.example", 0).result())
        .as("strict SPF alignment")
        .isEqualTo(AuthResult.FAIL);
    assertThat(dmarc(dns, "half.example", AuthResult.FAIL, "half.example", 10).disposition())
        .isEqualTo(Dmarc.Disposition.REJECT);
    assertThat(dmarc(dns, "half.example", AuthResult.FAIL, "half.example", 90).disposition())
        .as("outside the pct sample the next lower policy applies")
        .isEqualTo(Dmarc.Disposition.QUARANTINE);
    assertThat(dmarc(dns, "nodmarc.example", AuthResult.FAIL, "nodmarc.example", 0).result())
        .isEqualTo(AuthResult.NONE);
    assertThat(dmarc(dns, "broken.example", AuthResult.PASS, "broken.example", 0).result())
        .isEqualTo(AuthResult.TEMPERROR);
  }

  @Test
  void dmarcRecordParsing() {
    assertThat(Dmarc.parse("v=DMARC1; p=none")).isNotNull();
    assertThat(Dmarc.parse("p=reject; v=DMARC1")).as("v must come first").isNull();
    assertThat(Dmarc.parse("v=DMARC1; p=bogus")).isNull();
    assertThat(
            java.util.Objects.requireNonNull(
                    Dmarc.parse("v=DMARC1; p=bogus; rua=mailto:r@example.net"))
                .p())
        .isEqualTo(Dmarc.Disposition.NONE);
    assertThat(Dmarc.parse("v=spf1 -all")).isNull();
    assertThat(Dmarc.organizationalDomain("a.b.example.co.uk")).isEqualTo("example.co.uk");
  }
}
