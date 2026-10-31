package org.shem.http;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.util.List;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.shem.tls.Http01Challenges;

/** Port-80 challenge/redirect listener, MTA-STS hosting, and the admin certificate status. */
class HttpAcmeIT {
  private static final ObjectMapper JSON = new ObjectMapper();
  private static final List<String> HOSTS = List.of("mail.example.org", "mta-sts.example.org");
  @TempDir Path dir;
  private HttpFixture fixture;
  private final Http01Challenges challenges = new Http01Challenges();
  private ChallengeRole port80;
  private final HttpClient plain =
      HttpClient.newBuilder()
          .proxy(java.net.ProxySelector.of(null))
          .followRedirects(HttpClient.Redirect.NEVER)
          .build();

  @BeforeEach
  void setUp() throws Exception {
    fixture = new HttpFixture(dir);
    port80 =
        ChallengeRole.start(
            new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), challenges, HOSTS);
  }

  @AfterEach
  void tearDown() {
    port80.close();
    fixture.close();
  }

  private HttpResponse<String> plain(String method, String path, @Nullable String host)
      throws Exception {
    HttpRequest.Builder request =
        HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port80.port() + path))
            .method(method, HttpRequest.BodyPublishers.noBody());
    if (host != null) {
      request.header("Host", host);
    }
    return plain.send(request.build(), HttpResponse.BodyHandlers.ofString());
  }

  @Test
  void port80ServesOnlyActiveChallengeTokens() throws Exception {
    challenges.publish("abc_DEF-123", "abc_DEF-123.thumb");
    HttpResponse<String> answer =
        plain("GET", "/.well-known/acme-challenge/abc_DEF-123", "mail.example.org");
    assertThat(answer.statusCode()).isEqualTo(200);
    assertThat(answer.body()).isEqualTo("abc_DEF-123.thumb");
    assertThat(plain("GET", "/.well-known/acme-challenge/other", null).statusCode()).isEqualTo(404);
    challenges.withdraw("abc_DEF-123");
    assertThat(
            plain("GET", "/.well-known/acme-challenge/abc_DEF-123", "mail.example.org")
                .statusCode())
        .as("withdrawn after validation")
        .isEqualTo(404);
    assertThat(plain("POST", "/.well-known/acme-challenge/x", null).statusCode()).isEqualTo(405);
  }

  @Test
  void port80RedirectsOnlyToConfiguredHosts() throws Exception {
    HttpResponse<String> evil = plain("GET", "/api/v1/me", "evil.example");
    assertThat(evil.statusCode()).isEqualTo(301);
    assertThat(evil.headers().firstValue("Location"))
        .contains("https://mail.example.org/api/v1/me");
    assertThat(plain("GET", "/x", "MTA-STS.example.org:80").headers().firstValue("Location"))
        .contains("https://mta-sts.example.org/x");
    assertThat(plain("POST", "/api/v1/auth/login", "mail.example.org").statusCode())
        .as("no API or credentials over plain HTTP")
        .isEqualTo(405);
  }

  @Test
  void redirectPathsCannotChangeTheTarget() {
    assertThat(ChallengeRole.redirect("x", "//evil.example/a", HOSTS))
        .isEqualTo("https://mail.example.org/");
    assertThat(ChallengeRole.redirect("x", "/a\\b", HOSTS)).isEqualTo("https://mail.example.org/");
    assertThat(ChallengeRole.redirect(null, "/ok?no", HOSTS))
        .isEqualTo("https://mail.example.org/ok?no");
    assertThat(ChallengeRole.redirect("mail.example.org", "/" + "a".repeat(5000), HOSTS))
        .isEqualTo("https://mail.example.org/");
  }

  private HttpResponse<String> https(String path, String host) throws Exception {
    return fixture.client.send(
        HttpRequest.newBuilder(URI.create(fixture.base + path)).header("Host", host).GET().build(),
        HttpResponse.BodyHandlers.ofString());
  }

  @Test
  void mtaStsPolicyIsServedOnlyOnPolicyHostsOfLocalDomains() throws Exception {
    HttpResponse<String> policy = https("/.well-known/mta-sts.txt", "mta-sts.example.org");
    assertThat(policy.statusCode()).isEqualTo(200);
    assertThat(policy.headers().firstValue("Content-Type"))
        .hasValueSatisfying(v -> assertThat(v).startsWith("text/plain"));
    assertThat(policy.body())
        .isEqualTo("version: STSv1\r\nmode: testing\r\nmx: mx.example.org\r\nmax_age: 604800\r\n");
    assertThat(https("/.well-known/mta-sts.txt", "mta-sts.example.net").statusCode())
        .as("not a local domain")
        .isEqualTo(404);
    assertThat(https("/.well-known/mta-sts.txt", "mail.example.org").statusCode()).isEqualTo(404);
  }

  @Test
  void policyIdsFollowThePolicyText() {
    MtaStsPolicy testing = HttpFixture.MTA_STS;
    MtaStsPolicy enforce =
        new MtaStsPolicy(MtaStsPolicy.Mode.ENFORCE, testing.mx(), testing.maxAge());
    assertThat(testing.id()).matches("[0-9a-f]{20}").isEqualTo(HttpFixture.MTA_STS.id());
    assertThat(enforce.id()).isNotEqualTo(testing.id());
  }

  private String adminToken() throws Exception {
    HttpFixture.Response first =
        fixture.call(
            "POST",
            "/api/v1/admin/auth/login",
            JSON.createObjectNode()
                .put("name", HttpFixture.ADMIN)
                .put("password", HttpFixture.ADMIN_PASSWORD)
                .toString());
    HttpFixture.Response verified =
        fixture.call(
            "POST",
            "/api/v1/admin/auth/mfa/verify",
            JSON.createObjectNode()
                .put("challenge", JSON.readTree(first.body()).get("challenge").asText())
                .put("totp", fixture.totp(fixture.adminTotp))
                .put("bearer", true)
                .toString());
    return JSON.readTree(verified.body()).get("token").asText();
  }

  @Test
  void adminsSeeCertificateStateAndMtaStsDnsGuidance() throws Exception {
    String token = "Bearer " + adminToken();
    fixture.certificateStatus =
        new org.shem.tls.CertificateRenewal.Status(
            java.time.Instant.parse("2027-01-01T00:00:00Z"),
            java.time.Instant.parse("2026-12-01T00:00:00Z"),
            java.time.Instant.parse("2026-12-01T00:20:00Z"),
            2,
            "AcmeException",
            null);
    HttpFixture.Response tls =
        fixture.call("GET", "/api/v1/admin/tls", null, "Authorization", token);
    assertThat(tls.status()).isEqualTo(200);
    JsonNode status = JSON.readTree(tls.body());
    assertThat(status.get("consecutiveFailures").asInt()).isEqualTo(2);
    assertThat(status.get("lastError").asText()).isEqualTo("AcmeException");
    assertThat(status.get("notAfter").asText()).isEqualTo("2027-01-01T00:00:00Z");
    assertThat(fixture.call("GET", "/api/v1/admin/tls", null).status()).isEqualTo(401);

    String domain =
        fixture
            .identity
            .directory()
            .domainByName("example.org")
            .orElseThrow()
            .domainId()
            .toString();
    String dns =
        fixture
            .call("GET", "/api/v1/admin/domains/" + domain + "/dns", null, "Authorization", token)
            .body();
    assertThat(dns)
        .contains("mta-sts.example.org")
        .contains("_mta-sts.example.org")
        .contains("v=STSv1; id=" + HttpFixture.MTA_STS.id());
  }
}
