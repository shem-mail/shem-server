package org.shem.outbound;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.james.jdkim.DKIMVerifier;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.shem.delivery.MessageSource;
import org.shem.identity.Domain;

@SuppressWarnings(
    "StringConcatToTextBlock") // explicit CRLF line endings read better as concatenation
class MtaStsAndDkimTest {
  @TempDir Path dir;

  @Test
  void policyParsingAndMxMatching() {
    MtaSts.Policy policy =
        java.util.Objects.requireNonNull(
            MtaSts.parse(
                "version: STSv1\r\nmode: enforce\r\nmx: mail.example.net\r\nmx: *.example.org\r\nmax_age: 604800\r\n"));
    assertThat(policy.allows("mail.example.net")).isTrue();
    assertThat(policy.allows("mx1.example.org")).isTrue();
    assertThat(policy.allows("a.b.example.org")).as("wildcard covers one label").isFalse();
    assertThat(policy.allows("example.org")).isFalse();
    assertThat(MtaSts.parse("version: STSv1\nmode: enforce\nmax_age: 1\n"))
        .as("enforce needs mx")
        .isNull();
    assertThat(MtaSts.parse("version: STSv2\nmode: none\nmax_age: 1\n")).isNull();
  }

  @Test
  void cachedPolicySurvivesDiscoveryFailureAndRefreshesOnNewId() {
    OutboundFixture.MutableClock clock = new OutboundFixture.MutableClock();
    java.util.Map<String, List<String>> txt = new java.util.concurrent.ConcurrentHashMap<>();
    AtomicInteger fetches = new AtomicInteger();
    txt.put("_mta-sts.example.net", List.of("v=STSv1; id=a1"));
    MtaSts sts =
        new MtaSts(
            (name, type) -> {
              List<String> values = txt.get(name);
              if (values == null) {
                throw new org.shem.policy.DnsResolver.DnsTemporaryException("blocked");
              }
              return values;
            },
            domain -> {
              fetches.incrementAndGet();
              return "version: STSv1\nmode: enforce\nmx: mx.example.net\nmax_age: 3600\n";
            },
            clock);
    assertThat(sts.policy("example.net")).isNotNull();
    assertThat(sts.policy("example.net")).isNotNull();
    assertThat(fetches).hasValue(1);
    txt.remove("_mta-sts.example.net");
    assertThat(sts.policy("example.net"))
        .as("an attacker blocking DNS cannot downgrade")
        .isNotNull();
    txt.put("_mta-sts.example.net", List.of("v=STSv1; id=b2"));
    sts.policy("example.net");
    assertThat(fetches).hasValue(2);
    clock.now = clock.now.plus(Duration.ofHours(2));
    txt.remove("_mta-sts.example.net");
    assertThat(sts.policy("example.net")).as("expired after max_age").isNull();
  }

  @Test
  void policyFetchRefusesNonPublicAddresses() throws Exception {
    assertThat(HttpsPolicyFetcher.isPublic(InetAddress.getByName("93.184.216.34"))).isTrue();
    for (String internal :
        List.of(
            "127.0.0.1",
            "10.1.2.3",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "::1",
            "fd00::1",
            "0.0.0.0")) {
      assertThat(HttpsPolicyFetcher.isPublic(InetAddress.getByName(internal)))
          .as(internal)
          .isFalse();
    }
    HttpsPolicyFetcher fetcher =
        new HttpsPolicyFetcher(
            (name, type) ->
                type == org.shem.policy.DnsResolver.Type.A ? List.of("169.254.169.254") : List.of(),
            Duration.ofSeconds(1));
    assertThatThrownBy(() -> fetcher.fetch("evil.example"))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("public");
  }

  @Test
  void signedBytesVerifyAndKeysAreOwnerOnly() throws Exception {
    OutboundFixture fixture = new OutboundFixture(dir.resolve("f"));
    Domain domain = fixture.identity.directory().domainByName("example.org").orElseThrow();
    fixture.identity.setDkimSelector(domain.domainId(), "s2026");
    DkimSigning signing = new DkimSigning(dir.resolve("dkim"), fixture.identity);
    String record = signing.generate("s2026", "example.org");
    assertThat(Files.getPosixFilePermissions(signing.keyFile("s2026", "example.org")))
        .containsExactlyInAnyOrder(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
    assertThatThrownBy(() -> signing.generate("s2026", "example.org"))
        .as("no silent key replacement")
        .isInstanceOf(IOException.class);
    assertThat(signing.publishedRecord("s2026", "example.org")).contains(record);
    assertThat(signing.publishedRecord("other", "example.org")).isEmpty();

    byte[] message =
        "From: Alice <alice@example.org>\r\nTo: bob@example.net\r\nSubject: signed\r\nDate: Sun, 25 Oct 2026 10:00:00 +0000\r\n\r\nhello\r\n"
            .getBytes(StandardCharsets.UTF_8);
    MessageSource signed = signing.sign("example.org", MessageSource.ofBytes(message));
    byte[] bytes;
    try (var in = signed.open()) {
      bytes = in.readAllBytes();
    }
    assertThat(bytes).hasSize((int) signed.size());
    String text = new String(bytes, StandardCharsets.UTF_8);
    assertThat(text).startsWith("DKIM-Signature: ").contains("d=example.org").contains("s=s2026");

    DKIMVerifier verifier = new DKIMVerifier((method, selector, token) -> List.of(record));
    assertThat(verifier.verify(new ByteArrayInputStream(bytes))).hasSize(1);
    byte[] tampered = text.replace("hello", "jello").getBytes(StandardCharsets.UTF_8);
    assertThatThrownBy(
            () ->
                new DKIMVerifier((m, s, t) -> List.of(record))
                    .verify(new ByteArrayInputStream(tampered)))
        .isInstanceOf(Exception.class);

    MessageSource unsigned = signing.sign("other.example", MessageSource.ofBytes(message));
    assertThat(unsigned.size()).as("no key for the domain: unchanged").isEqualTo(message.length);
  }
}
