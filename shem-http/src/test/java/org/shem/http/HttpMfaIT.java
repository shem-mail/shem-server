package org.shem.http;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Path;
import java.time.Duration;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.shem.crypto.Secret;

class HttpMfaIT {
  private static final ObjectMapper JSON = new ObjectMapper();
  private static final String CAROL = "carol@example.org";
  private static final String CAROL_PASSWORD = "carol has a long passphrase";
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

  private static JsonNode json(HttpFixture.Response r) throws Exception {
    return JSON.readTree(r.body());
  }

  private static String credentials(String user, String password) {
    return JSON.createObjectNode().put("username", user).put("password", password).toString();
  }

  private HttpFixture.Response as(
      HttpApiIT.Browser b,
      String method,
      String path,
      @org.jspecify.annotations.Nullable String body)
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

  /** Carol: enrolled with a password but no second factor yet. */
  private void enrollCarol() throws Exception {
    String bootstrap = fixture.provision(CAROL);
    HttpFixture.Response login =
        fixture.call("POST", "/api/v1/auth/login", credentials(CAROL, bootstrap));
    HttpApiIT.Browser b = HttpApiIT.browser(login);
    assertThat(
            as(
                    b,
                    "POST",
                    "/api/v1/me/enrollment",
                    JSON.createObjectNode().put("newPassword", CAROL_PASSWORD).toString())
                .status())
        .isEqualTo(200);
  }

  private HttpFixture.Response verify(String challenge, String field, Object value)
      throws Exception {
    var body = JSON.createObjectNode().put("challenge", challenge);
    if (value instanceof JsonNode node) {
      body.set(field, node);
    } else {
      body.put(field, String.valueOf(value));
    }
    return fixture.call("POST", "/api/v1/auth/mfa/verify", body.toString());
  }

  @Test
  void accountsWithoutAFactorMustEnrollOneBeforeAnythingElse() throws Exception {
    enrollCarol();
    HttpApiIT.Browser b =
        HttpApiIT.browser(
            fixture.call("POST", "/api/v1/auth/login", credentials(CAROL, CAROL_PASSWORD)));
    assertThat(
            json(fixture.call("GET", "/api/v1/me", null, "Cookie", b.cookie()))
                .get("mfaEnrollmentRequired")
                .asBoolean())
        .isTrue();
    assertThat(fixture.call("GET", "/api/v1/me/app-passwords", null, "Cookie", b.cookie()).status())
        .isEqualTo(403);
    assertThat(as(b, "POST", "/api/v1/me/recovery-code", "{}").status()).isEqualTo(403);

    HttpFixture.Response started = as(b, "POST", "/api/v1/me/mfa/totp", "{}");
    assertThat(started.status()).isEqualTo(200);
    String base32 = json(started).get("secret").asText();
    assertThat(json(started).get("uri").asText())
        .startsWith("otpauth://totp/Shem:carol%40example.org?secret=" + base32);
    Secret secret = Secret.wrap(base32Decode(base32));
    assertThat(as(b, "POST", "/api/v1/me/mfa/totp/confirm", "{\"code\":\"000000\"}").status())
        .isEqualTo(400);
    String firstCode = fixture.totp(secret);
    assertThat(
            as(
                    b,
                    "POST",
                    "/api/v1/me/mfa/totp/confirm",
                    JSON.createObjectNode().put("code", firstCode).put("label", "phone").toString())
                .status())
        .isEqualTo(201);
    assertThat(fixture.call("GET", "/api/v1/me/app-passwords", null, "Cookie", b.cookie()).status())
        .as("the session is complete once a factor exists")
        .isEqualTo(200);

    HttpFixture.Response login =
        fixture.call("POST", "/api/v1/auth/login", credentials(CAROL, CAROL_PASSWORD));
    assertThat(json(login).get("mfaRequired").asBoolean()).isTrue();
    assertThat(json(login).get("methods").toString()).isEqualTo("[\"totp\"]");
    assertThat(login.header("Set-Cookie")).isNull();
    String challenge = json(login).get("challenge").asText();
    assertThat(verify(challenge, "totp", firstCode).status())
        .as("the enrollment code cannot be replayed")
        .isEqualTo(401);
    assertThat(verify(challenge, "totp", fixture.totp(secret)).status()).isEqualTo(200);
    assertThat(verify(challenge, "totp", fixture.totp(secret)).status())
        .as("challenge is single use")
        .isEqualTo(401);
  }

  @Test
  void pendingLoginsAreBoundedInAttemptsAndTime() throws Exception {
    String challenge =
        json(fixture.call(
                "POST", "/api/v1/auth/login", credentials(HttpFixture.ALICE, HttpFixture.PASSWORD)))
            .get("challenge")
            .asText();
    for (int i = 0; i < SessionStore.MAX_FACTOR_ATTEMPTS; i++) {
      assertThat(verify(challenge, "totp", "000000").status()).isEqualTo(401);
    }
    assertThat(verify(challenge, "totp", fixture.totp(fixture.aliceTotp)).status())
        .as("attempts exhausted: the pending login is gone")
        .isEqualTo(401);

    String late =
        json(fixture.call(
                "POST", "/api/v1/auth/login", credentials(HttpFixture.ALICE, HttpFixture.PASSWORD)))
            .get("challenge")
            .asText();
    fixture.clock.advance(SessionStore.PENDING_LIFETIME.plusSeconds(1));
    assertThat(verify(late, "totp", fixture.totp(fixture.aliceTotp)).status()).isEqualTo(401);
    assertThat(
            fixture.registry.isUnlocked(
                fixture.identity.loginAccount(HttpFixture.ALICE).orElseThrow().mailboxId()))
        .as("expired pending logins release the mailbox")
        .isFalse();

    // Five failures above plus five more reach the account limit of ten.
    for (int round = 0; round < 1; round++) {
      String c =
          json(fixture.call(
                  "POST",
                  "/api/v1/auth/login",
                  credentials(HttpFixture.ALICE, HttpFixture.PASSWORD)))
              .get("challenge")
              .asText();
      for (int i = 0; i < SessionStore.MAX_FACTOR_ATTEMPTS; i++) {
        verify(c, "totp", "111111");
      }
    }
    assertThat(
            fixture
                .call(
                    "POST",
                    "/api/v1/auth/login",
                    credentials(HttpFixture.ALICE, HttpFixture.PASSWORD))
                .status())
        .as("too many recent factor failures for the account")
        .isEqualTo(429);
    fixture.clock.advance(SessionStore.FAILURE_WINDOW.plusSeconds(1));
    assertThat(
            fixture
                .call(
                    "POST",
                    "/api/v1/auth/login",
                    credentials(HttpFixture.ALICE, HttpFixture.PASSWORD))
                .status())
        .isEqualTo(200);
  }

  @Test
  void webAuthnRegistrationAndLoginAndTheLastFactorRule() throws Exception {
    enrollCarol();
    HttpApiIT.Browser b =
        HttpApiIT.browser(
            fixture.call("POST", "/api/v1/auth/login", credentials(CAROL, CAROL_PASSWORD)));
    TestAuthenticator key = new TestAuthenticator(HttpFixture.ORIGIN, "localhost");
    JsonNode options = json(as(b, "POST", "/api/v1/me/mfa/webauthn/options", "{}"));
    assertThat(options.get("rp").get("id").asText()).isEqualTo("localhost");
    assertThat(options.get("attestation").asText()).isEqualTo("none");
    String wrong = TestAuthenticator.b64(new byte[32]);
    assertThat(
            as(b, "POST", "/api/v1/me/mfa/webauthn", key.register(wrong, "key").toString())
                .status())
        .as("a response for another challenge is refused")
        .isEqualTo(400);
    options = json(as(b, "POST", "/api/v1/me/mfa/webauthn/options", "{}"));
    HttpFixture.Response registered =
        as(
            b,
            "POST",
            "/api/v1/me/mfa/webauthn",
            key.register(options.get("challenge").asText(), "yubikey").toString());
    assertThat(registered.status()).isEqualTo(201);
    String keyId = json(registered).get("id").asText();
    assertThat(as(b, "DELETE", "/api/v1/me/mfa/" + keyId, null).status())
        .as("cannot remove the last factor")
        .isEqualTo(409);

    JsonNode login =
        json(fixture.call("POST", "/api/v1/auth/login", credentials(CAROL, CAROL_PASSWORD)));
    assertThat(login.get("methods").toString()).isEqualTo("[\"webauthn\"]");
    String challenge = login.get("challenge").asText();
    JsonNode request =
        json(
            fixture.call(
                "POST",
                "/api/v1/auth/mfa/webauthn-options",
                JSON.createObjectNode().put("challenge", challenge).toString()));
    assertThat(request.get("allowCredentials").get(0).get("id").asText())
        .isEqualTo(key.credentialId());
    JsonNode assertion = key.assertion(request.get("challenge").asText());
    HttpFixture.Response done = verify(challenge, "webauthn", assertion);
    assertThat(done.status()).isEqualTo(200);
    HttpApiIT.Browser second = HttpApiIT.browser(done);

    // A replayed assertion (same counter) never works, even with a fresh challenge.
    String again =
        json(fixture.call("POST", "/api/v1/auth/login", credentials(CAROL, CAROL_PASSWORD)))
            .get("challenge")
            .asText();
    fixture.call(
        "POST",
        "/api/v1/auth/mfa/webauthn-options",
        JSON.createObjectNode().put("challenge", again).toString());
    assertThat(verify(again, "webauthn", assertion).status()).isEqualTo(401);

    // With a second factor, the first can be removed (after step-up).
    HttpFixture.Response totp = as(second, "POST", "/api/v1/me/mfa/totp", "{}");
    Secret secret = Secret.wrap(base32Decode(json(totp).get("secret").asText()));
    assertThat(
            as(
                    second,
                    "POST",
                    "/api/v1/me/mfa/totp/confirm",
                    JSON.createObjectNode().put("code", fixture.totp(secret)).toString())
                .status())
        .isEqualTo(201);
    assertThat(as(second, "DELETE", "/api/v1/me/mfa/" + keyId, null).status()).isEqualTo(204);
    JsonNode factors = json(fixture.call("GET", "/api/v1/me/mfa", null, "Cookie", second.cookie()));
    assertThat(factors.get("factors").toString()).contains("totp").doesNotContain("webauthn");
    fixture.clock.advance(Duration.ofMinutes(1));
  }

  private static byte[] base32Decode(String value) {
    String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
    int buffer = 0;
    int bits = 0;
    for (int i = 0; i < value.length(); i++) {
      char c = value.charAt(i);
      buffer = (buffer << 5) | alphabet.indexOf(c);
      bits += 5;
      if (bits >= 8) {
        out.write((buffer >> (bits - 8)) & 0xff);
        bits -= 8;
      }
    }
    return out.toByteArray();
  }
}
