package org.shem.http;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.InetAddress;
import java.nio.file.Path;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.shem.mailbox.AuthenticationException;
import org.shem.mailbox.Capability;
import org.shem.mailbox.MailboxLease;

class HttpApiIT {
  private static final ObjectMapper JSON = new ObjectMapper();
  @TempDir Path dir;
  private HttpFixture fixture;

  @BeforeEach
  void setUp() throws Exception {
    fixture = new HttpFixture(dir);
  }

  @AfterEach
  void tearDown() {
    fixture.close();
  }

  /** A cookie session: the cookie header value and the CSRF token. */
  record Browser(String cookie, String csrf) {}

  static JsonNode json(HttpFixture.Response response) throws Exception {
    return JSON.readTree(response.body());
  }

  private static String credentials(String user, String password) throws Exception {
    return JSON.createObjectNode().put("username", user).put("password", password).toString();
  }

  private Browser login(String user, String password) throws Exception {
    HttpFixture.Response response =
        fixture.call(
            "POST",
            "/api/v1/auth/login",
            credentials(user, password),
            "Origin",
            HttpFixture.ORIGIN);
    assertThat(response.status()).isEqualTo(200);
    if (json(response).path("mfaRequired").asBoolean(false)) {
      assertThat(response.header("Set-Cookie")).as("no session before the second factor").isNull();
      response =
          fixture.call(
              "POST",
              "/api/v1/auth/mfa/verify",
              JSON.createObjectNode()
                  .put("challenge", json(response).get("challenge").asText())
                  .put("totp", fixture.totp(fixture.aliceTotp))
                  .toString(),
              "Origin",
              HttpFixture.ORIGIN);
      assertThat(response.status()).isEqualTo(200);
    }
    return browser(response);
  }

  static Browser browser(HttpFixture.Response response) throws Exception {
    String setCookie = java.util.Objects.requireNonNull(response.header("Set-Cookie"));
    assertThat(setCookie)
        .startsWith(Api.COOKIE + "=")
        .contains("Secure")
        .contains("HttpOnly")
        .contains("SameSite=Strict")
        .contains("Path=/");
    return new Browser(
        setCookie.substring(0, setCookie.indexOf(';')), json(response).get("csrfToken").asText());
  }

  private HttpFixture.Response as(
      Browser b, String method, String path, @org.jspecify.annotations.Nullable String body)
      throws Exception {
    return fixture.call(
        method,
        path,
        body,
        "Cookie",
        b.cookie(),
        "X-CSRF-Token",
        b.csrf(),
        "Origin",
        HttpFixture.ORIGIN);
  }

  private String mailboxId() {
    return fixture.identity.loginAccount(HttpFixture.ALICE).orElseThrow().mailboxId().toString();
  }

  private boolean unlocked() {
    return fixture.registry.isUnlocked(
        fixture.identity.loginAccount(HttpFixture.ALICE).orElseThrow().mailboxId());
  }

  @Test
  void sessionHoldsTheUnlockedMailboxUntilLogout() throws Exception {
    Browser b = login(HttpFixture.ALICE, HttpFixture.PASSWORD);
    assertThat(unlocked()).isTrue();
    HttpFixture.Response me = fixture.call("GET", "/api/v1/me", null, "Cookie", b.cookie());
    assertThat(me.status()).isEqualTo(200);
    JsonNode body = json(me);
    assertThat(body.get("address").asText()).isEqualTo(HttpFixture.ALICE);
    assertThat(body.get("credential").asText()).isEqualTo("password");
    assertThat(body.toString()).contains("key_administration").doesNotContain("token\"");
    assertThat(me.header("Cache-Control")).isEqualTo("no-store");
    assertThat(me.header("Access-Control-Allow-Origin")).isNull();
    assertThat(me.header("Content-Security-Policy")).contains("default-src 'none'");

    assertThat(fixture.call("POST", "/api/v1/auth/logout", null, "Cookie", b.cookie()).status())
        .as("logout without CSRF token")
        .isEqualTo(403);
    assertThat(as(b, "POST", "/api/v1/auth/logout", null).status()).isEqualTo(204);
    assertThat(fixture.call("GET", "/api/v1/me", null, "Cookie", b.cookie()).status())
        .isEqualTo(401);
    assertThat(unlocked()).as("last session ended: mailbox locked").isFalse();
    assertThat(mailboxId()).isNotEmpty();
  }

  @Test
  void loginFailuresAreIndistinguishableAndAppPasswordsCannotLogIn() throws Exception {
    Browser b = login(HttpFixture.ALICE, HttpFixture.PASSWORD);
    HttpFixture.Response created =
        as(
            b,
            "POST",
            "/api/v1/me/app-passwords",
            JSON.createObjectNode().put("label", "phone").toString());
    assertThat(created.status()).isEqualTo(201);
    String appPassword = json(created).get("password").asText();

    HttpFixture.Response wrong =
        fixture.call(
            "POST", "/api/v1/auth/login", credentials(HttpFixture.ALICE, "wrong password"));
    HttpFixture.Response unknown =
        fixture.call(
            "POST", "/api/v1/auth/login", credentials("nobody@example.org", "wrong password"));
    HttpFixture.Response app =
        fixture.call("POST", "/api/v1/auth/login", credentials(HttpFixture.ALICE, appPassword));
    assertThat(wrong.status()).isEqualTo(401);
    assertThat(unknown.body()).isEqualTo(wrong.body());
    assertThat(app.body()).isEqualTo(wrong.body());
    assertThat(wrong.header("Content-Type")).isEqualTo("application/problem+json");
  }

  @Test
  void bootstrapSessionsCanOnlyEnroll() throws Exception {
    String bootstrap = fixture.provision("carol@example.org");
    Browser b = login("carol@example.org", bootstrap);
    JsonNode me = json(fixture.call("GET", "/api/v1/me", null, "Cookie", b.cookie()));
    assertThat(me.get("enrollmentRequired").asBoolean()).isTrue();
    assertThat(me.get("state").asText()).isEqualTo("pending_enrollment");
    assertThat(fixture.call("GET", "/api/v1/me/app-passwords", null, "Cookie", b.cookie()).status())
        .isEqualTo(403);
    assertThat(as(b, "POST", "/api/v1/me/enrollment", "{\"newPassword\":\"short\"}").status())
        .isEqualTo(409);
    HttpFixture.Response enrolled =
        as(b, "POST", "/api/v1/me/enrollment", "{\"newPassword\":\"a much better passphrase\"}");
    assertThat(enrolled.status()).isEqualTo(200);
    assertThat(json(enrolled).get("reauthenticate").asBoolean()).isTrue();
    assertThat(fixture.call("GET", "/api/v1/me", null, "Cookie", b.cookie()).status())
        .isEqualTo(401);
    assertThat(
            fixture
                .call("POST", "/api/v1/auth/login", credentials("carol@example.org", bootstrap))
                .status())
        .as("bootstrap credential is gone")
        .isEqualTo(401);
    Browser carol = login("carol@example.org", "a much better passphrase");
    assertThat(
            json(fixture.call("GET", "/api/v1/me", null, "Cookie", carol.cookie()))
                .get("mfaEnrollmentRequired")
                .asBoolean())
        .isTrue();
  }

  @Test
  void crossOriginAndCsrfProtection() throws Exception {
    assertThat(
            fixture
                .call(
                    "POST",
                    "/api/v1/auth/login",
                    credentials(HttpFixture.ALICE, HttpFixture.PASSWORD),
                    "Origin",
                    "https://evil.example")
                .status())
        .isEqualTo(403);
    Browser b = login(HttpFixture.ALICE, HttpFixture.PASSWORD);
    String body = JSON.createObjectNode().put("label", "x").toString();
    assertThat(
            fixture
                .call(
                    "POST",
                    "/api/v1/me/app-passwords",
                    body,
                    "Cookie",
                    b.cookie(),
                    "X-CSRF-Token",
                    "guess")
                .status())
        .isEqualTo(403);
    assertThat(
            fixture
                .call(
                    "POST",
                    "/api/v1/me/app-passwords",
                    body,
                    "Cookie",
                    b.cookie(),
                    "X-CSRF-Token",
                    b.csrf(),
                    "Sec-Fetch-Site",
                    "cross-site")
                .status())
        .isEqualTo(403);

    HttpFixture.Response challenge =
        fixture.call(
            "POST", "/api/v1/auth/login", credentials(HttpFixture.ALICE, HttpFixture.PASSWORD));
    HttpFixture.Response bearerLogin =
        fixture.call(
            "POST",
            "/api/v1/auth/mfa/verify",
            JSON.createObjectNode()
                .put("challenge", json(challenge).get("challenge").asText())
                .put("totp", fixture.totp(fixture.aliceTotp))
                .put("bearer", true)
                .toString());
    assertThat(bearerLogin.header("Set-Cookie")).as("bearer clients get no cookie").isNull();
    String token = json(bearerLogin).get("token").asText();
    assertThat(
            fixture
                .call("POST", "/api/v1/me/app-passwords", body, "Authorization", "Bearer " + token)
                .status())
        .isEqualTo(201);
  }

  @Test
  void sensitiveOperationsRequireRecentAuthentication() throws Exception {
    Browser b = login(HttpFixture.ALICE, HttpFixture.PASSWORD);
    fixture.clock.advance(HttpFixture.STEP_UP.plusSeconds(1));
    String label = JSON.createObjectNode().put("label", "laptop").toString();
    assertThat(as(b, "POST", "/api/v1/me/app-passwords", label).status()).isEqualTo(403);
    assertThat(
            as(
                    b,
                    "POST",
                    "/api/v1/me/app-passwords",
                    JSON.createObjectNode()
                        .put("label", "laptop")
                        .put("currentPassword", "nope")
                        .toString())
                .status())
        .isEqualTo(401);
    HttpFixture.Response created =
        as(
            b,
            "POST",
            "/api/v1/me/app-passwords",
            JSON.createObjectNode()
                .put("label", "laptop")
                .put("currentPassword", HttpFixture.PASSWORD)
                .toString());
    assertThat(created.status()).isEqualTo(201);
    String id = json(created).get("id").asText();
    String appPassword = json(created).get("password").asText();
    MailboxLease client =
        fixture.sessions.authenticate(
            HttpFixture.ALICE,
            appPassword,
            InetAddress.getLoopbackAddress(),
            Capability.MAIL_ACCESS);

    JsonNode list =
        json(fixture.call("GET", "/api/v1/me/app-passwords", null, "Cookie", b.cookie()));
    assertThat(list.get("appPasswords").toString()).contains("laptop").doesNotContain(appPassword);
    assertThat(as(b, "DELETE", "/api/v1/me/app-passwords/" + id, null).status()).isEqualTo(204);
    assertThat(client.isValid()).as("revoking the slot ends its live sessions").isFalse();
    assertThat(as(b, "DELETE", "/api/v1/me/app-passwords/" + id, null).status()).isEqualTo(404);
  }

  @Test
  void otherSessionsCanBeEndedAndPasswordChangeEndsThem() throws Exception {
    Browser b = login(HttpFixture.ALICE, HttpFixture.PASSWORD);
    Browser other = login(HttpFixture.ALICE, HttpFixture.PASSWORD);
    String appPassword =
        json(as(b, "POST", "/api/v1/me/app-passwords", "{\"label\":\"phone\"}"))
            .get("password")
            .asText();
    MailboxLease client =
        fixture.sessions.authenticate(
            HttpFixture.ALICE,
            appPassword,
            InetAddress.getLoopbackAddress(),
            Capability.MAIL_ACCESS);

    fixture.clock.advance(HttpFixture.STEP_UP.plusSeconds(1));
    assertThat(as(b, "DELETE", "/api/v1/me/other-sessions", null).status())
        .as("needs a recent credential check")
        .isEqualTo(403);
    assertThat(
            as(b, "DELETE", "/api/v1/me/other-sessions", "{\"currentPassword\":\"nope\"}").status())
        .isEqualTo(401);
    assertThat(fixture.call("GET", "/api/v1/me", null, "Cookie", other.cookie()).status())
        .as("a refused request ends nothing")
        .isEqualTo(200);
    HttpFixture.Response ended =
        as(
            b,
            "DELETE",
            "/api/v1/me/other-sessions",
            JSON.createObjectNode().put("currentPassword", HttpFixture.PASSWORD).toString());
    assertThat(ended.status()).isEqualTo(200);
    assertThat(json(ended).get("endedSessions").asInt()).isEqualTo(2);
    assertThat(fixture.call("GET", "/api/v1/me", null, "Cookie", other.cookie()).status())
        .isEqualTo(401);
    assertThat(client.isValid()).as("mail client sessions end too").isFalse();
    assertThat(fixture.call("GET", "/api/v1/me", null, "Cookie", b.cookie()).status())
        .as("the caller's own session stays")
        .isEqualTo(200);
    assertThat(unlocked()).isTrue();

    // Password change ends other sessions, including ones that unlocked the same password slot.
    Browser third = login(HttpFixture.ALICE, HttpFixture.PASSWORD);
    assertThat(
            as(b, "PUT", "/api/v1/me/password", "{\"newPassword\":\"another passphrase 2026\"}")
                .status())
        .isEqualTo(204);
    assertThat(fixture.call("GET", "/api/v1/me", null, "Cookie", third.cookie()).status())
        .isEqualTo(401);
    assertThat(fixture.call("GET", "/api/v1/me", null, "Cookie", b.cookie()).status())
        .isEqualTo(200);
  }

  @Test
  void idleSessionsExpireAndRevocationEndsThem() throws Exception {
    Browser b = login(HttpFixture.ALICE, HttpFixture.PASSWORD);
    fixture.clock.advance(HttpFixture.IDLE.plusSeconds(1));
    assertThat(fixture.call("GET", "/api/v1/me", null, "Cookie", b.cookie()).status())
        .isEqualTo(401);
    assertThat(unlocked()).isFalse();

    Browser again = login(HttpFixture.ALICE, HttpFixture.PASSWORD);
    fixture.registry.revokeMailbox(
        fixture.identity.loginAccount(HttpFixture.ALICE).orElseThrow().mailboxId());
    assertThat(fixture.call("GET", "/api/v1/me", null, "Cookie", again.cookie()).status())
        .isEqualTo(401);
  }

  @Test
  void recoveryCodeReplacesThePasswordOnce() throws Exception {
    Browser b = login(HttpFixture.ALICE, HttpFixture.PASSWORD);
    HttpFixture.Response created = as(b, "POST", "/api/v1/me/recovery-code", "{}");
    assertThat(created.status()).isEqualTo(201);
    String code = json(created).get("code").asText();

    String recovery =
        JSON.createObjectNode().put("username", HttpFixture.ALICE).put("code", code).toString();
    HttpFixture.Response login = fixture.call("POST", "/api/v1/auth/recovery", recovery);
    assertThat(login.status()).isEqualTo(200);
    Browser r =
        new Browser(
            java.util.Objects.requireNonNull(login.header("Set-Cookie")).replaceAll(";.*", ""),
            json(login).get("csrfToken").asText());
    assertThat(json(login).get("capabilities").toString()).isEqualTo("[\"key_administration\"]");
    HttpFixture.Response changed =
        as(r, "PUT", "/api/v1/me/password", "{\"newPassword\":\"recovered passphrase 2026\"}");
    assertThat(changed.status()).isEqualTo(200);
    assertThat(json(changed).get("reauthenticate").asBoolean()).isTrue();
    assertThat(fixture.call("GET", "/api/v1/me", null, "Cookie", b.cookie()).status())
        .as("recovery ends every other session")
        .isEqualTo(401);
    assertThat(fixture.call("POST", "/api/v1/auth/recovery", recovery).status())
        .as("single use")
        .isEqualTo(401);
    assertThat(
            fixture
                .call(
                    "POST",
                    "/api/v1/auth/login",
                    credentials(HttpFixture.ALICE, HttpFixture.PASSWORD))
                .status())
        .isEqualTo(401);
    login(HttpFixture.ALICE, "recovered passphrase 2026");
  }

  @Test
  void requestValidationAndSessionCaps() throws Exception {
    assertThat(fixture.call("POST", "/api/v1/auth/login", "{\"username\":1}").status())
        .isEqualTo(400);
    assertThat(fixture.call("POST", "/api/v1/auth/login", "{not json").status()).isEqualTo(400);
    assertThat(
            fixture.call("POST", "/api/v1/auth/login", "{}", "Content-Type", "text/plain").status())
        .isEqualTo(415);
    assertThat(
            fixture
                .call("POST", "/api/v1/auth/login", "{\"username\":\"" + "x".repeat(20_000) + "\"}")
                .status())
        .isEqualTo(413);
    assertThat(fixture.call("GET", "/api/v1/nothing", null).status()).isEqualTo(404);
    assertThat(fixture.call("PUT", "/api/v1/me", null).status()).isEqualTo(405);
    assertThat(fixture.call("GET", "/healthz", null).body()).isEqualTo("ok");
    for (int i = 0; i < 3; i++) {
      login(HttpFixture.ALICE, HttpFixture.PASSWORD);
    }
    HttpFixture.Response pending =
        fixture.call(
            "POST", "/api/v1/auth/login", credentials(HttpFixture.ALICE, HttpFixture.PASSWORD));
    assertThat(
            fixture
                .call(
                    "POST",
                    "/api/v1/auth/mfa/verify",
                    JSON.createObjectNode()
                        .put("challenge", json(pending).get("challenge").asText())
                        .put("totp", fixture.totp(fixture.aliceTotp))
                        .toString())
                .status())
        .as("per-account session cap")
        .isEqualTo(429);
    assertThat(AuthenticationException.Reason.values()).isNotEmpty();
  }
}
