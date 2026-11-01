package org.shem.http;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.shem.common.OpaqueId;
import org.shem.crypto.MfaFactor;
import org.shem.crypto.Secret;
import org.shem.crypto.Totp;
import org.shem.identity.AccountState;
import org.shem.mailbox.Capability;
import org.shem.mailbox.MailboxExport;
import org.shem.mailbox.MailboxLease;
import org.shem.store.SpecialUse;
import org.shem.store.metadata.Flags;
import org.shem.store.metadata.Folder;

class HttpExportAndJobsIT {
  private static final ObjectMapper JSON = new ObjectMapper();
  private static final String BOB = "bob@example.org";
  private static final String BOB_PASSWORD = "bob also has a long passphrase";
  private static final String EXPORT_BODY = "{\"format\":\"" + MailboxExport.FORMAT + "\"}";
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

  private HttpApiIT.Browser login(String user, String password, Secret totp) throws Exception {
    HttpFixture.Response first =
        fixture.call(
            "POST",
            "/api/v1/auth/login",
            JSON.createObjectNode().put("username", user).put("password", password).toString(),
            "Origin",
            HttpFixture.ORIGIN);
    HttpFixture.Response verified =
        fixture.call(
            "POST",
            "/api/v1/auth/mfa/verify",
            JSON.createObjectNode()
                .put("challenge", json(first).get("challenge").asText())
                .put("totp", fixture.totp(totp))
                .toString(),
            "Origin",
            HttpFixture.ORIGIN);
    assertThat(verified.status()).isEqualTo(200);
    return HttpApiIT.browser(verified);
  }

  private HttpApiIT.Browser alice() throws Exception {
    return login(HttpFixture.ALICE, HttpFixture.PASSWORD, fixture.aliceTotp);
  }

  private HttpFixture.Response as(
      HttpApiIT.Browser b, String method, String path, @Nullable String body, String... extra)
      throws Exception {
    String[] headers = new String[6 + extra.length];
    headers[0] = "Cookie";
    headers[1] = b.cookie();
    headers[2] = "X-CSRF-Token";
    headers[3] = b.csrf();
    headers[4] = "Origin";
    headers[5] = HttpFixture.ORIGIN;
    System.arraycopy(extra, 0, headers, 6, extra.length);
    return fixture.call(method, path, body, headers);
  }

  private HttpResponse<InputStream> download(HttpApiIT.Browser b, String path) throws Exception {
    return fixture.client.send(
        HttpRequest.newBuilder(URI.create(fixture.base + path))
            .header("Cookie", b.cookie())
            .GET()
            .build(),
        HttpResponse.BodyHandlers.ofInputStream());
  }

  private OpaqueId aliceId() {
    return fixture.identity.directory().accounts().stream()
        .filter(a -> a.address().toString().equals(HttpFixture.ALICE))
        .findFirst()
        .orElseThrow()
        .mailboxId();
  }

  private void appendToAlice(int count, int bodyBytes) throws Exception {
    try (MailboxLease lease =
        fixture.sessions.authenticatePrimary(
            HttpFixture.ALICE, HttpFixture.PASSWORD, InetAddress.getLoopbackAddress())) {
      Folder inbox = lease.read(v -> v.folderByRole(SpecialUse.INBOX).orElseThrow());
      byte[] filler = new byte[bodyBytes];
      for (int i = 0; i < count; i++) {
        HttpFixture.RANDOM.nextBytes(filler);
        String body = java.util.Base64.getMimeEncoder().encodeToString(filler);
        byte[] message =
            ("Subject: export " + i + "\r\n\r\n" + body + "\r\n").getBytes(StandardCharsets.UTF_8);
        lease.append(
            inbox.folderId(),
            new ByteArrayInputStream(message),
            i == 0 ? new Flags(Flags.SEEN, java.util.List.of()) : Flags.NONE,
            Instant.parse("2026-10-25T10:00:00Z").toEpochMilli());
      }
    }
  }

  /** Bob: a second enrolled account with a TOTP factor, created through the services. */
  private Secret enrollBob() throws Exception {
    String bootstrap = fixture.provision(BOB);
    try (MailboxLease lease =
        fixture.sessions.authenticate(
            BOB, bootstrap, InetAddress.getLoopbackAddress(), Capability.ENROLL)) {
      fixture.lifecycle.enroll(lease, BOB_PASSWORD);
    }
    Secret totp = Totp.generateSecret(HttpFixture.RANDOM);
    try (MailboxLease lease =
        fixture.sessions.authenticatePrimary(BOB, BOB_PASSWORD, InetAddress.getLoopbackAddress())) {
      fixture.lifecycle.addFactor(
          lease,
          new MfaFactor(
              OpaqueId.random(HttpFixture.RANDOM),
              MfaFactor.Kind.TOTP,
              "phone",
              fixture.clock.instant(),
              0,
              totp.copy()));
    }
    return totp;
  }

  // ---- export ----

  @Test
  void exportStreamsTheMailboxOnceToTheSessionThatAskedForIt() throws Exception {
    appendToAlice(3, 300);
    HttpApiIT.Browser alice = alice();
    assertThat(as(alice, "POST", "/api/v1/me/exports", "{\"format\":\"pst\"}").status())
        .isEqualTo(400);
    HttpFixture.Response ticket = as(alice, "POST", "/api/v1/me/exports", EXPORT_BODY);
    assertThat(ticket.status()).isEqualTo(201);
    String content = json(ticket).get("content").asText();

    HttpApiIT.Browser other = alice();
    assertThat(download(other, content).statusCode())
        .as("bound to the negotiating session")
        .isEqualTo(404);

    HttpResponse<InputStream> response = download(alice, content);
    assertThat(response.statusCode()).isEqualTo(200);
    assertThat(response.headers().firstValue("Content-Type")).contains("application/zip");
    assertThat(response.headers().firstValue("Cache-Control")).contains("no-store");
    Map<String, String> entries = new HashMap<>();
    try (ZipInputStream zip = new ZipInputStream(response.body())) {
      ZipEntry entry;
      while ((entry = zip.getNextEntry()) != null) {
        entries.put(entry.getName(), new String(zip.readAllBytes(), StandardCharsets.UTF_8));
      }
    }
    assertThat(entries).containsKey("manifest.json");
    assertThat(entries.get("manifest.json")).contains("\"name\":\"INBOX\"").contains("\\\\Seen");
    String mbox =
        entries.entrySet().stream()
            .filter(e -> e.getValue().contains("Subject: export 0"))
            .findFirst()
            .orElseThrow()
            .getValue();
    assertThat(mbox).contains("Subject: export 1").contains("Subject: export 2");

    assertThat(download(alice, content).statusCode()).as("single use").isEqualTo(404);
  }

  @Test
  void exportTicketsExpireAndNeedRecentAuthentication() throws Exception {
    HttpApiIT.Browser alice = alice();
    String content =
        json(as(alice, "POST", "/api/v1/me/exports", EXPORT_BODY)).get("content").asText();
    fixture.clock.advance(Api.EXPORT_TICKET.plusSeconds(1));
    assertThat(download(alice, content).statusCode()).isEqualTo(404);
    assertThat(as(alice, "POST", "/api/v1/me/exports", EXPORT_BODY).status())
        .as("older than the step-up window")
        .isEqualTo(403);
    HttpFixture.Response fresh =
        as(
            alice,
            "POST",
            "/api/v1/me/exports",
            JSON.createObjectNode()
                .put("format", MailboxExport.FORMAT)
                .put("currentPassword", HttpFixture.PASSWORD)
                .toString());
    assertThat(fresh.status()).isEqualTo(201);
  }

  @Test
  void revokingTheMailboxMidExportBreaksTheTransfer() throws Exception {
    appendToAlice(120, 48 * 1024);
    HttpApiIT.Browser alice = alice();
    String content =
        json(as(alice, "POST", "/api/v1/me/exports", EXPORT_BODY)).get("content").asText();
    HttpResponse<InputStream> response = download(alice, content);
    assertThat(response.statusCode()).isEqualTo(200);
    try (InputStream in = response.body()) {
      assertThat(in.read()).isNotNegative();
      fixture.registry.revokeMailbox(aliceId());
      assertThatThrownBy(
              () -> {
                byte[] buffer = new byte[64 * 1024];
                while (in.read(buffer) >= 0) {
                  // drain until the server drops the connection
                }
              })
          .as("an aborted export is a transport error, never a clean end of body")
          .isInstanceOf(IOException.class);
    }
  }

  // ---- key rotation jobs ----

  private JsonNode awaitJob(HttpApiIT.Browser b, String location) throws Exception {
    long deadline = System.nanoTime() + Duration.ofSeconds(30).toNanos();
    while (true) {
      JsonNode job = json(as(b, "GET", location, null));
      if (!job.get("status").asText().equals("running") || System.nanoTime() > deadline) {
        return job;
      }
      Thread.sleep(10);
    }
  }

  @Test
  void keyRotationRunsAsAJobVisibleOnlyToItsOwner() throws Exception {
    HttpApiIT.Browser alice = alice();
    HttpApiIT.Browser otherAlice = alice();
    String before = fixture.identity.account(aliceId()).orElseThrow().publicKey().fingerprint();
    assertThat(as(alice, "POST", "/api/v1/me/key-rotations", "{}").status()).isEqualTo(400);
    assertThat(
            as(
                    alice,
                    "POST",
                    "/api/v1/me/key-rotations",
                    "{\"currentPassword\":\"not the password at all\"}")
                .status())
        .isEqualTo(401);

    String request = "{\"currentPassword\":\"" + HttpFixture.PASSWORD + "\"}";
    HttpFixture.Response started =
        as(alice, "POST", "/api/v1/me/key-rotations", request, "Idempotency-Key", "rotate-1");
    assertThat(started.status()).isEqualTo(202);
    String location = Objects.requireNonNull(started.header("Location"));
    assertThat(location).isEqualTo("/api/v1/jobs/" + json(started).get("id").asText());

    JsonNode done = awaitJob(alice, location);
    assertThat(done.get("status").asText()).isEqualTo("succeeded");
    assertThat(done.get("type").asText()).isEqualTo("key-rotation");
    assertThat(fixture.identity.account(aliceId()).orElseThrow().publicKey().fingerprint())
        .isNotEqualTo(before);

    HttpFixture.Response replay =
        as(alice, "POST", "/api/v1/me/key-rotations", request, "Idempotency-Key", "rotate-1");
    assertThat(json(replay).get("id").asText())
        .as("same idempotency key, same job")
        .isEqualTo(json(started).get("id").asText());

    assertThat(as(alice, "GET", "/api/v1/me", null).status())
        .as("the requesting session survives the rotation")
        .isEqualTo(200);
    assertThat(as(otherAlice, "GET", "/api/v1/me", null).status())
        .as("every other session ends, also one that unlocked the same password slot")
        .isEqualTo(401);

    Secret bobTotp = enrollBob();
    HttpApiIT.Browser bob = login(BOB, BOB_PASSWORD, bobTotp);
    assertThat(as(bob, "GET", location, null).status())
        .as("another user's job is indistinguishable from a missing one")
        .isEqualTo(404);
    assertThat(as(bob, "GET", "/api/v1/jobs/not-an-id", null).status()).isEqualTo(404);
    bobTotp.close();
  }

  @Test
  void aRotationInterruptedByLogoutIsReportedAndCompletesLater() throws Exception {
    HttpApiIT.Browser alice = alice();
    HttpApiIT.Browser observer = alice();
    // Logging out revokes the session's lease, which cancels the job's child lease as well.
    HttpFixture.Response started =
        as(
            alice,
            "POST",
            "/api/v1/me/key-rotations",
            "{\"currentPassword\":\"" + HttpFixture.PASSWORD + "\"}");
    assertThat(started.status()).isEqualTo(202);
    as(alice, "POST", "/api/v1/auth/logout", null);
    String location = Objects.requireNonNull(started.header("Location"));
    long deadline = System.nanoTime() + Duration.ofSeconds(30).toNanos();
    HttpFixture.Response polled;
    while (true) {
      polled = as(observer, "GET", location, null);
      if (polled.status() != 200
          || !json(polled).get("status").asText().equals("running")
          || System.nanoTime() > deadline) {
        break;
      }
      Thread.sleep(10);
    }
    if (polled.status() == 200) {
      assertThat(json(polled).get("status").asText())
          .as("stopped before the commit point, so the observer's session survives")
          .isEqualTo("interrupted");
    } else {
      assertThat(polled.status())
          .as("past the commit point the rotation ends every other session, the observer's too")
          .isEqualTo(401);
    }
    // Whatever the race, the next unlock leaves the mailbox usable with the new password.
    try (MailboxLease lease =
        fixture.sessions.authenticatePrimary(
            HttpFixture.ALICE, HttpFixture.PASSWORD, InetAddress.getLoopbackAddress())) {
      Boolean inbox = lease.read(v -> v.folderByRole(SpecialUse.INBOX).isPresent());
      assertThat(inbox).isTrue();
    }
  }

  // ---- account deletion ----

  @Test
  void usersCanStartDelayedDeletionOfTheirOwnAccount() throws Exception {
    HttpApiIT.Browser alice = alice();
    HttpFixture.Response recoveryCode = as(alice, "POST", "/api/v1/me/recovery-code", "{}");
    HttpFixture.Response recovery =
        fixture.call(
            "POST",
            "/api/v1/auth/recovery",
            JSON.createObjectNode()
                .put("username", HttpFixture.ALICE)
                .put("code", json(recoveryCode).get("code").asText())
                .toString());
    HttpApiIT.Browser recovering =
        new HttpApiIT.Browser(
            Objects.requireNonNull(recovery.header("Set-Cookie")).replaceAll(";.*", ""),
            json(recovery).get("csrfToken").asText());
    assertThat(as(recovering, "DELETE", "/api/v1/me", null).status())
        .as("a recovery session cannot delete the account")
        .isEqualTo(403);

    fixture.clock.advance(Duration.ofMinutes(6));
    assertThat(as(alice, "DELETE", "/api/v1/me", null).status())
        .as("needs a recent credential check")
        .isEqualTo(403);
    HttpFixture.Response deleted =
        as(alice, "DELETE", "/api/v1/me", "{\"currentPassword\":\"" + HttpFixture.PASSWORD + "\"}");
    assertThat(deleted.status()).isEqualTo(200);
    assertThat(json(deleted).get("state").asText()).isEqualTo("deletion_pending");
    assertThat(json(deleted).get("note").asText()).contains("Backups");
    assertThat(fixture.identity.account(aliceId()).orElseThrow().state())
        .isEqualTo(AccountState.DELETION_PENDING);
    assertThat(as(alice, "GET", "/api/v1/me", null).status()).isEqualTo(401);
    assertThat(
            fixture
                .call(
                    "POST",
                    "/api/v1/auth/login",
                    JSON.createObjectNode()
                        .put("username", HttpFixture.ALICE)
                        .put("password", HttpFixture.PASSWORD)
                        .toString())
                .status())
        .isEqualTo(401);
  }
}
