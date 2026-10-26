package org.shem.http;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Contract tests driven by the published OpenAPI document: every documented operation exists,
 * undocumented methods are refused, and each operation rejects the principals it is not for.
 */
class OpenApiContractIT {
  private static final ObjectMapper JSON = new ObjectMapper();
  private static final Set<String> METHODS = Set.of("get", "post", "put", "patch", "delete");
  @TempDir Path dir;
  private HttpFixture fixture;
  private JsonNode contract;

  /** One documented operation. */
  record Operation(String method, String template, String principal, boolean hasBody) {
    String path() {
      return template.replaceAll("\\{[^}]+}", "0123456789abcdef0123456789abcdef");
    }
  }

  @BeforeEach
  void setUp() throws Exception {
    fixture = new HttpFixture(dir);
    try (InputStream in = Api.class.getResourceAsStream("openapi.json")) {
      contract = JSON.readTree(java.util.Objects.requireNonNull(in));
    }
  }

  @AfterEach
  void tearDown() {
    fixture.close();
  }

  private List<Operation> operations() {
    List<Operation> out = new ArrayList<>();
    for (Map.Entry<String, JsonNode> path : contract.get("paths").properties()) {
      for (Map.Entry<String, JsonNode> op : path.getValue().properties()) {
        out.add(
            new Operation(
                op.getKey().toUpperCase(java.util.Locale.ROOT),
                path.getKey(),
                op.getValue().get("x-shem-principal").asText(),
                op.getValue().has("requestBody")));
      }
    }
    return out;
  }

  private HttpFixture.Response call(Operation op, String... auth) throws Exception {
    List<String> headers = new ArrayList<>(List.of("Origin", HttpFixture.ORIGIN));
    headers.addAll(List.of(auth));
    return fixture.call(
        op.method(), op.path(), op.hasBody() ? "{}" : null, headers.toArray(String[]::new));
  }

  private String mailboxToken() throws Exception {
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
    return JSON.readTree(verified.body()).get("token").asText();
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
  void theServedContractIsThePackagedOne() throws Exception {
    HttpFixture.Response served = fixture.call("GET", "/api/v1/openapi.json", null);
    assertThat(served.status()).isEqualTo(200);
    assertThat(JSON.readTree(served.body())).isEqualTo(contract);
    assertThat(contract.get("openapi").asText()).startsWith("3.");
    for (Operation op : operations()) {
      assertThat(op.principal()).as(op.toString()).isIn("public", "mailbox", "admin");
    }
  }

  @Test
  void everyDocumentedOperationExistsAndRefusesAnonymousCallers() throws Exception {
    for (Operation op : operations()) {
      int status = call(op).status();
      assertThat(status).as(op + " is routed").isNotIn(404, 405);
      if (!op.principal().equals("public")) {
        assertThat(status).as(op + " needs a session").isEqualTo(401);
      }
    }
  }

  @Test
  void undocumentedMethodsOnDocumentedPathsAreRefused() throws Exception {
    for (Map.Entry<String, JsonNode> path : contract.get("paths").properties()) {
      for (String method : METHODS) {
        if (!path.getValue().has(method)) {
          Operation op =
              new Operation(
                  method.toUpperCase(java.util.Locale.ROOT), path.getKey(), "public", false);
          assertThat(call(op).status()).as(op.toString()).isEqualTo(405);
        }
      }
    }
  }

  @Test
  void mailboxAndAdminSessionsCannotCrossOver() throws Exception {
    String mailbox = "Bearer " + mailboxToken();
    String admin = "Bearer " + adminToken();
    for (Operation op : operations()) {
      if (op.principal().equals("admin")) {
        assertThat(call(op, "Authorization", mailbox).status())
            .as(op + " with a mailbox session")
            .isEqualTo(401);
      } else if (op.principal().equals("mailbox")) {
        assertThat(call(op, "Authorization", admin).status())
            .as(op + " with an admin session")
            .isEqualTo(401);
      }
    }
  }
}
