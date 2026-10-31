package org.shem.http;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayInputStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Base64;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.shem.mailbox.MailboxLease;
import org.shem.search.AttachmentIndex;
import org.shem.store.SpecialUse;
import org.shem.store.metadata.Flags;
import org.shem.store.metadata.Folder;

class HttpAttachmentSearchIT {
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

  private static byte[] withAttachment(String type, String content) {
    return ("From: bob@example.net\r\nSubject: s\r\nMIME-Version: 1.0\r\n"
            + "Content-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nbody\r\n--B\r\n"
            + "Content-Type: "
            + type
            + "\r\nContent-Disposition: attachment; filename=\"f.pdf\"\r\nContent-Transfer-Encoding: base64\r\n\r\n"
            + Base64.getMimeEncoder().encodeToString(content.getBytes(StandardCharsets.UTF_8))
            + "\r\n--B--\r\n")
        .getBytes(StandardCharsets.US_ASCII);
  }

  private String token() throws Exception {
    HttpFixture.Response first =
        fixture.call(
            "POST",
            "/api/v1/auth/login",
            JSON.createObjectNode()
                .put("username", HttpFixture.ALICE)
                .put("password", HttpFixture.PASSWORD)
                .toString());
    HttpFixture.Response verified =
        fixture.call(
            "POST",
            "/api/v1/auth/mfa/verify",
            JSON.createObjectNode()
                .put("challenge", JSON.readTree(first.body()).get("challenge").asText())
                .put("totp", fixture.totp(fixture.aliceTotp))
                .put("bearer", true)
                .toString());
    return "Bearer " + JSON.readTree(verified.body()).get("token").asText();
  }

  private HttpFixture.Response search(String token, String query, boolean allowIncomplete)
      throws Exception {
    return fixture.call(
        "POST",
        "/api/v1/me/attachment-searches",
        JSON.createObjectNode()
            .put("query", query)
            .put("allowIncomplete", allowIncomplete)
            .toString(),
        "Authorization",
        token);
  }

  private void append(byte[] message) throws Exception {
    try (MailboxLease lease =
        fixture.sessions.authenticatePrimary(
            HttpFixture.ALICE, HttpFixture.PASSWORD, InetAddress.getLoopbackAddress())) {
      Folder inbox = lease.read(v -> v.folderByRole(SpecialUse.INBOX).orElseThrow());
      lease.append(inbox.folderId(), new ByteArrayInputStream(message), Flags.NONE, 0);
      assertThat(
              lease
                  .extension(AttachmentIndex.class)
                  .orElseThrow()
                  .awaitIdle(Duration.ofSeconds(30)))
          .isTrue();
    }
  }

  @Test
  void returnsFolderAndUidReferencesAndListsIncompleteMessages() throws Exception {
    String token = token();
    append(withAttachment("application/pdf", "Invoice NUMBER 4711"));
    append(withAttachment("application/x-locked", "unreadable"));
    HttpFixture.Response response = search(token, "invoice number", false);
    assertThat(response.status()).isEqualTo(200);
    JsonNode result = JSON.readTree(response.body());
    assertThat(result.get("matches")).hasSize(1);
    assertThat(result.get("matches").get(0).get("folder").asText()).isEqualTo("INBOX");
    assertThat(result.get("matches").get(0).get("uid").asLong()).isEqualTo(1);
    assertThat(result.get("incomplete")).hasSize(1);
    assertThat(result.get("incomplete").get(0).get("uid").asLong()).isEqualTo(2);
    assertThat(result.get("complete").asBoolean()).isFalse();
    assertThat(result.get("pending").asLong()).isZero();
    assertThat(search(token, "ab", false).status()).isEqualTo(400);
  }

  @Test
  void pendingExtractionIsAnErrorUnlessIncompleteResultsAreAccepted() throws Exception {
    String token = token();
    fixture.attachments.available = false;
    append(withAttachment("application/pdf", "waiting text"));
    HttpFixture.Response refused = search(token, "waiting", false);
    assertThat(refused.status()).isEqualTo(409);
    assertThat(refused.body()).contains("1 messages are still pending");
    JsonNode partial = JSON.readTree(search(token, "waiting", true).body());
    assertThat(partial.get("pending").asLong()).isEqualTo(1);
    assertThat(partial.get("complete").asBoolean()).isFalse();
    assertThat(partial.get("matches")).isEmpty();
  }

  @Test
  void needsAFullMailboxSession() throws Exception {
    assertThat(
            fixture.call("POST", "/api/v1/me/attachment-searches", "{\"query\":\"abc\"}").status())
        .isEqualTo(401);
  }
}
