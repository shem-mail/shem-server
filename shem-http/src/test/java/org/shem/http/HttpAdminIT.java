package org.shem.http;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.shem.common.OpaqueId;

class HttpAdminIT {
  private static final ObjectMapper JSON = new ObjectMapper();
  @TempDir Path dir;
  private HttpFixture fixture;

  /** An admin browser session: cookie plus CSRF token. */
  record Admin(String cookie, String csrf) {}

  @BeforeEach
  void setUp() throws Exception {
    fixture = new HttpFixture(dir);
  }

  @AfterEach
  void tearDown() {
    fixture.close();
  }

  private static JsonNode json(HttpFixture.Response r) throws Exception {
    return JSON.readTree(r.body());
  }

  private HttpFixture.Response post(String path, String body) throws Exception {
    return fixture.call("POST", path, body, "Origin", HttpFixture.ORIGIN);
  }

  private HttpFixture.Response password(String name, String password) throws Exception {
    return post(
        "/api/v1/admin/auth/login",
        JSON.createObjectNode().put("name", name).put("password", password).toString());
  }

  private Admin login() throws Exception {
    HttpFixture.Response first = password(HttpFixture.ADMIN, HttpFixture.ADMIN_PASSWORD);
    assertThat(first.status()).isEqualTo(200);
    assertThat(json(first).get("mfaRequired").asBoolean()).isTrue();
    assertThat(first.header("Set-Cookie")).as("no session before TOTP").isNull();
    HttpFixture.Response second =
        post(
            "/api/v1/admin/auth/mfa/verify",
            JSON.createObjectNode()
                .put("challenge", json(first).get("challenge").asText())
                .put("totp", fixture.totp(fixture.adminTotp))
                .toString());
    assertThat(second.status()).isEqualTo(200);
    String setCookie = Objects.requireNonNull(second.header("Set-Cookie"));
    assertThat(setCookie)
        .startsWith(AdminApi.COOKIE + "=")
        .contains("Secure")
        .contains("HttpOnly")
        .contains("SameSite=Strict");
    return new Admin(
        setCookie.substring(0, setCookie.indexOf(';')), json(second).get("csrfToken").asText());
  }

  private HttpFixture.Response as(
      Admin a, String method, String path, @Nullable String body, String... extra)
      throws Exception {
    String[] headers = new String[6 + extra.length];
    headers[0] = "Cookie";
    headers[1] = a.cookie();
    headers[2] = "X-CSRF-Token";
    headers[3] = a.csrf();
    headers[4] = "Origin";
    headers[5] = HttpFixture.ORIGIN;
    System.arraycopy(extra, 0, headers, 6, extra.length);
    return fixture.call(method, path, body, headers);
  }

  private static String body(String field, String value) {
    return JSON.createObjectNode().put(field, value).toString();
  }

  @Test
  void loginNeedsPasswordAndTotp() throws Exception {
    assertThat(password(HttpFixture.ADMIN, "wrong password entirely").status()).isEqualTo(401);
    assertThat(password("nobody", HttpFixture.ADMIN_PASSWORD).status()).isEqualTo(401);
    HttpFixture.Response first = password(HttpFixture.ADMIN, HttpFixture.ADMIN_PASSWORD);
    HttpFixture.Response wrong =
        post(
            "/api/v1/admin/auth/mfa/verify",
            JSON.createObjectNode()
                .put("challenge", json(first).get("challenge").asText())
                .put("totp", "000000")
                .toString());
    assertThat(wrong.status()).isEqualTo(401);
    assertThat(wrong.header("Set-Cookie")).isNull();

    Admin admin = login();
    HttpFixture.Response me = as(admin, "GET", "/api/v1/admin/me", null);
    assertThat(me.status()).isEqualTo(200);
    assertThat(json(me).get("admin").asText()).isEqualTo(HttpFixture.ADMIN);

    assertThat(as(admin, "POST", "/api/v1/admin/auth/logout", null).status()).isEqualTo(204);
    assertThat(as(admin, "GET", "/api/v1/admin/me", null).status()).isEqualTo(401);
  }

  @Test
  void adminAndMailboxSessionsAreSeparate() throws Exception {
    Admin admin = login();
    String mailboxCookie = admin.cookie().replace(AdminApi.COOKIE, Api.COOKIE);
    assertThat(fixture.call("GET", "/api/v1/me", null, "Cookie", mailboxCookie).status())
        .as("an admin token is not a mailbox session")
        .isEqualTo(401);
    assertThat(
            fixture
                .call(
                    "GET",
                    "/api/v1/admin/me",
                    null,
                    "Authorization",
                    "Bearer " + admin.cookie().substring(admin.cookie().indexOf('=') + 1))
                .status())
        .as("the same token works as a bearer on admin routes")
        .isEqualTo(200);
    assertThat(fixture.call("GET", "/api/v1/admin/domains", null).status()).isEqualTo(401);
  }

  @Test
  void cookieMutationsRequireCsrfAndOrigin() throws Exception {
    Admin admin = login();
    assertThat(
            fixture
                .call(
                    "POST",
                    "/api/v1/admin/domains",
                    body("name", "example.net"),
                    "Cookie",
                    admin.cookie(),
                    "Origin",
                    HttpFixture.ORIGIN)
                .status())
        .isEqualTo(403);
    assertThat(
            fixture
                .call(
                    "POST",
                    "/api/v1/admin/domains",
                    body("name", "example.net"),
                    "Cookie",
                    admin.cookie(),
                    "X-CSRF-Token",
                    admin.csrf(),
                    "Origin",
                    "https://evil.example")
                .status())
        .isEqualTo(403);
    assertThat(fixture.identity.directory().domainByName("example.net")).isEmpty();
  }

  @Test
  void domainsDkimAndDnsGuidance() throws Exception {
    Admin admin = login();
    HttpFixture.Response created =
        as(admin, "POST", "/api/v1/admin/domains", body("name", "Example.NET"));
    assertThat(created.status()).isEqualTo(201);
    String id = json(created).get("id").asText();
    assertThat(json(created).get("name").asText()).isEqualTo("example.net");
    assertThat(as(admin, "POST", "/api/v1/admin/domains", body("name", "example.net")).status())
        .isEqualTo(409);

    assertThat(
            as(
                    admin,
                    "POST",
                    "/api/v1/admin/domains/" + id + "/dkim-rotations",
                    body("selector", "Bad!"))
                .status())
        .isEqualTo(400);
    HttpFixture.Response dkim =
        as(
            admin,
            "POST",
            "/api/v1/admin/domains/" + id + "/dkim-rotations",
            body("selector", "s2026"));
    assertThat(dkim.status()).isEqualTo(201);
    assertThat(json(dkim).get("name").asText()).isEqualTo("s2026._domainkey.example.net");
    assertThat(
            as(
                    admin,
                    "POST",
                    "/api/v1/admin/domains/" + id + "/dkim-rotations",
                    body("selector", "s2026"))
                .status())
        .as("keys are never replaced")
        .isEqualTo(409);

    JsonNode dns = json(as(admin, "GET", "/api/v1/admin/domains/" + id + "/dns", null));
    assertThat(dns.get("records").toString())
        .contains("10 mx.example.org.")
        .contains("v=spf1 mx -all")
        .contains("_dmarc.example.net")
        .contains("s2026._domainkey.example.net")
        .contains(json(dkim).get("value").asText());

    long version =
        fixture
            .identity
            .directory()
            .domain(Objects.requireNonNull(OpaqueId.parseOrNull(id)))
            .orElseThrow()
            .version();
    assertThat(as(admin, "DELETE", "/api/v1/admin/domains/" + id, null).status()).isEqualTo(428);
    assertThat(
            as(admin, "DELETE", "/api/v1/admin/domains/" + id, null, "If-Match", "\"999\"")
                .status())
        .isEqualTo(412);
    assertThat(
            as(
                    admin,
                    "DELETE",
                    "/api/v1/admin/domains/" + id,
                    null,
                    "If-Match",
                    "\"" + version + "\"")
                .status())
        .isEqualTo(204);
    assertThat(fixture.identity.directory().domainByName("example.net")).isEmpty();
  }

  @Test
  void destructiveChangesNeedRecentAuthentication() throws Exception {
    Admin admin = login();
    String id =
        json(as(admin, "POST", "/api/v1/admin/domains", body("name", "example.net")))
            .get("id")
            .asText();
    fixture.clock.advance(Duration.ofMinutes(6));
    assertThat(
            as(admin, "DELETE", "/api/v1/admin/domains/" + id, null, "If-Match", "\"1\"").status())
        .isEqualTo(403);
    assertThat(
            as(
                    admin,
                    "POST",
                    "/api/v1/admin/domains/" + id + "/dkim-rotations",
                    body("selector", "s1"))
                .status())
        .isEqualTo(403);
    assertThat(as(admin, "GET", "/api/v1/admin/domains", null).status())
        .as("ordinary reads still work")
        .isEqualTo(200);
  }

  @Test
  void idleAdminSessionsExpire() throws Exception {
    Admin admin = login();
    fixture.clock.advance(AdminSessionStore.IDLE.plusSeconds(1));
    assertThat(as(admin, "GET", "/api/v1/admin/me", null).status()).isEqualTo(401);
  }

  @Test
  void accountsAreProvisionedWithAOneTimeBootstrapPassword() throws Exception {
    Admin admin = login();
    HttpFixture.Response created =
        as(
            admin,
            "POST",
            "/api/v1/admin/accounts",
            JSON.createObjectNode()
                .put("address", "dave@example.org")
                .put("quotaBytes", 1 << 20)
                .toString());
    assertThat(created.status()).isEqualTo(201);
    JsonNode account = json(created);
    String bootstrap = account.get("bootstrapPassword").asText();
    assertThat(bootstrap).isNotBlank();
    assertThat(account.has("bootstrapExpiresAt")).isTrue();

    JsonNode list = json(as(admin, "GET", "/api/v1/admin/accounts", null));
    assertThat(list.toString()).contains("dave@example.org").doesNotContain(bootstrap);

    HttpFixture.Response mailboxLogin =
        post(
            "/api/v1/auth/login",
            JSON.createObjectNode()
                .put("username", "dave@example.org")
                .put("password", bootstrap)
                .toString());
    assertThat(mailboxLogin.status()).as("the user enrolls with it").isEqualTo(200);
  }

  @Test
  void blockingAnAccountEndsItsSessions() throws Exception {
    HttpFixture.Response first =
        post(
            "/api/v1/auth/login",
            JSON.createObjectNode()
                .put("username", HttpFixture.ALICE)
                .put("password", HttpFixture.PASSWORD)
                .toString());
    HttpFixture.Response verified =
        post(
            "/api/v1/auth/mfa/verify",
            JSON.createObjectNode()
                .put("challenge", json(first).get("challenge").asText())
                .put("totp", fixture.totp(fixture.aliceTotp))
                .toString());
    HttpApiIT.Browser alice = HttpApiIT.browser(verified);
    assertThat(fixture.call("GET", "/api/v1/me", null, "Cookie", alice.cookie()).status())
        .isEqualTo(200);

    Admin admin = login();
    JsonNode account =
        fixture.identity.directory().accounts().stream()
            .filter(a -> a.address().toString().equals(HttpFixture.ALICE))
            .map(
                a ->
                    JSON.createObjectNode()
                        .put("id", a.mailboxId().toString())
                        .put("version", a.version()))
            .findFirst()
            .orElseThrow();
    String path = "/api/v1/admin/accounts/" + account.get("id").asText();
    assertThat(
            as(
                    admin,
                    "PATCH",
                    path,
                    JSON.createObjectNode()
                        .put("version", account.get("version").asLong() + 7)
                        .put("state", "blocked")
                        .toString())
                .status())
        .isEqualTo(412);
    HttpFixture.Response blocked =
        as(
            admin,
            "PATCH",
            path,
            JSON.createObjectNode()
                .put("version", account.get("version").asLong())
                .put("state", "blocked")
                .toString());
    assertThat(blocked.status()).isEqualTo(200);
    assertThat(json(blocked).get("state").asText()).isEqualTo("blocked");
    assertThat(
            fixture.registry.isUnlocked(
                Objects.requireNonNull(OpaqueId.parseOrNull(account.get("id").asText()))))
        .as("the mailbox is locked again")
        .isFalse();
    assertThat(fixture.call("GET", "/api/v1/me", null, "Cookie", alice.cookie()).status())
        .isEqualTo(401);
  }

  @Test
  void aliasesUseExistingAccountsAsSenders() throws Exception {
    Admin admin = login();
    HttpFixture.Response invalid =
        as(
            admin,
            "POST",
            "/api/v1/admin/aliases",
            "{\"address\":\"team@example.org\",\"targets\":[\"alice@example.org\"],"
                + "\"senders\":[\"ghost@example.org\"]}");
    assertThat(invalid.status()).isEqualTo(400);
    HttpFixture.Response created =
        as(
            admin,
            "POST",
            "/api/v1/admin/aliases",
            "{\"address\":\"team@example.org\",\"targets\":[\"alice@example.org\"],"
                + "\"senders\":[\"alice@example.org\"]}");
    assertThat(created.status()).isEqualTo(201);
    JsonNode alias = json(created);
    assertThat(alias.get("senders").get(0).asText()).isEqualTo(HttpFixture.ALICE);
    String path = "/api/v1/admin/aliases/" + alias.get("id").asText();
    HttpFixture.Response updated =
        as(
            admin,
            "PATCH",
            path,
            "{\"version\":"
                + alias.get("version").asLong()
                + ",\"targets\":[\"alice@example.org\"]}");
    assertThat(updated.status()).isEqualTo(200);
    assertThat(json(updated).get("senders").size()).isZero();
    assertThat(as(admin, "PATCH", path, "{\"version\":0,\"targets\":[]}").status())
        .as("stale version")
        .isEqualTo(412);
    alias = json(updated);
    assertThat(
            as(admin, "DELETE", path, null, "If-Match", "\"" + alias.get("version").asLong() + "\"")
                .status())
        .isEqualTo(204);
    assertThat(json(as(admin, "GET", "/api/v1/admin/aliases", null)).get("aliases").size())
        .isZero();
  }

  @Test
  void deletingAnAccountStartsDelayedDeletion() throws Exception {
    Admin admin = login();
    JsonNode dave =
        json(as(admin, "POST", "/api/v1/admin/accounts", body("address", "dave@example.org")));
    String path = "/api/v1/admin/accounts/" + dave.get("id").asText();
    assertThat(json(as(admin, "GET", path, null)).get("address").asText())
        .isEqualTo("dave@example.org");
    assertThat(json(as(admin, "GET", path, null)).has("bootstrapPassword"))
        .as("shown only at creation")
        .isFalse();
    assertThat(as(admin, "DELETE", path, null).status()).isEqualTo(428);
    HttpFixture.Response deleted =
        as(admin, "DELETE", path, null, "If-Match", "\"" + dave.get("version").asLong() + "\"");
    assertThat(deleted.status()).isEqualTo(200);
    assertThat(json(deleted).get("state").asText()).isEqualTo("deletion_pending");
    assertThat(
            post(
                    "/api/v1/auth/login",
                    JSON.createObjectNode()
                        .put("username", "dave@example.org")
                        .put("password", dave.get("bootstrapPassword").asText())
                        .toString())
                .status())
        .isEqualTo(401);
    assertThat(as(admin, "GET", "/api/v1/admin/accounts/" + "A".repeat(26), null).status())
        .isEqualTo(404);
  }

  @Test
  void noRouteReadsMailOrRecoversAMailbox() throws Exception {
    Admin admin = login();
    String id = fixture.identity.directory().accounts().get(0).mailboxId().toString();
    for (String path :
        new String[] {
          "/api/v1/admin/accounts/" + id + "/messages",
          "/api/v1/admin/accounts/" + id + "/password",
          "/api/v1/admin/accounts/" + id + "/export",
          "/api/v1/admin/accounts/" + id + "/keys"
        }) {
      assertThat(as(admin, "GET", path, null).status()).as(path).isEqualTo(404);
      assertThat(as(admin, "POST", path, "{}").status()).as(path).isEqualTo(404);
    }
  }

  @Test
  void adminChangesAreAuditedAndRefusedWhenTheAuditLogFails() throws Exception {
    Admin admin = login();
    String id =
        json(as(admin, "POST", "/api/v1/admin/domains", body("name", "example.net")))
            .get("id")
            .asText();
    List<String> records = java.nio.file.Files.readAllLines(fixture.audit.file());
    assertThat(records)
        .anyMatch(r -> r.contains(" admin:root auth.password - ok "))
        .anyMatch(r -> r.contains(" admin:root auth.totp - ok "))
        .anyMatch(r -> r.contains(" admin:root domains.post - attempt "))
        .anyMatch(r -> r.contains(" admin:root domains.post " + id + " ok "));
    assertThat(String.join("\n", records)).doesNotContain("example.net");
    assertThat(org.shem.identity.AuditLog.verifyFile(fixture.audit.file()))
        .isEqualTo(records.size());

    fixture.audit.close();
    assertThat(as(admin, "POST", "/api/v1/admin/domains", body("name", "example.com")).status())
        .isEqualTo(503);
    assertThat(fixture.identity.directory().domainByName("example.com"))
        .as("fail closed: no unaudited change")
        .isEmpty();
  }
}
