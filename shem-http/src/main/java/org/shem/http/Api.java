package org.shem.http;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import org.jspecify.annotations.Nullable;
import org.shem.common.OpaqueId;
import org.shem.crypto.KdfAdmission;
import org.shem.crypto.Secret;
import org.shem.crypto.SlotDescriptor;
import org.shem.crypto.SlotKind;
import org.shem.identity.Account;
import org.shem.identity.IdentityService;
import org.shem.mailbox.AuthenticationException;
import org.shem.mailbox.Capability;
import org.shem.mailbox.KeyLifecycle;
import org.shem.mailbox.MailboxLease;
import org.shem.mailbox.SessionService;

/**
 * The {@code /api/v1} routes. Every response carries {@code Cache-Control: no-store} and strict
 * security headers; errors are RFC 9457 problem documents with fixed, non-identifying details.
 * Cookie-authenticated mutations need a matching {@code Origin} and the session's {@code
 * X-CSRF-Token}; bearer tokens (for non-browser clients) skip CSRF but follow the same session,
 * timeout, and revocation rules. No CORS headers are ever sent. Nothing about a request is logged.
 */
final class Api implements HttpHandler {
  static final String COOKIE = "__Host-shem-session";
  private static final System.Logger LOG = System.getLogger(Api.class.getName());
  private static final int MAX_USERNAME = 320;
  private static final int MAX_SECRET = 1024;
  private static final int MAX_LABEL = 64;

  private final HttpSettings settings;
  private final SessionStore sessions;
  private final SessionService auth;
  private final KeyLifecycle lifecycle;
  private final IdentityService identity;
  private final Clock clock;
  private final ObjectMapper json =
      new ObjectMapper()
          .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
          .enable(DeserializationFeature.FAIL_ON_READING_DUP_TREE_KEY);

  Api(
      HttpSettings settings,
      SessionStore sessions,
      SessionService auth,
      KeyLifecycle lifecycle,
      IdentityService identity,
      Clock clock) {
    this.settings = settings;
    this.sessions = sessions;
    this.auth = auth;
    this.lifecycle = lifecycle;
    this.identity = identity;
    this.clock = clock;
  }

  /** One request's context. */
  private final class Call {
    final HttpExchange exchange;
    final String method;
    final String path;
    @Nullable String token;
    boolean bearer;

    Call(HttpExchange exchange) {
      this.exchange = exchange;
      this.method = exchange.getRequestMethod().toUpperCase(Locale.ROOT);
      this.path = exchange.getRequestURI().getRawPath();
      String authorization = exchange.getRequestHeaders().getFirst("Authorization");
      if (authorization != null && authorization.regionMatches(true, 0, "Bearer ", 0, 7)) {
        token = authorization.substring(7).strip();
        bearer = true;
      } else {
        token = cookie(exchange.getRequestHeaders());
      }
    }

    InetAddress source() {
      return exchange.getRemoteAddress().getAddress();
    }

    SessionStore.Session session() throws ApiException {
      String t = token;
      if (t == null) {
        throw ApiException.unauthorized();
      }
      SessionStore.Session session = sessions.find(t).orElseThrow(ApiException::unauthorized);
      if (!bearer && !method.equals("GET")) {
        String csrf = exchange.getRequestHeaders().getFirst("X-CSRF-Token");
        if (csrf == null
            || !java.security.MessageDigest.isEqual(
                csrf.getBytes(StandardCharsets.US_ASCII),
                session.csrfToken.getBytes(StandardCharsets.US_ASCII))) {
          throw ApiException.forbidden();
        }
      }
      return session;
    }
  }

  @Override
  public void handle(HttpExchange exchange) throws IOException {
    try (exchange) {
      securityHeaders(exchange.getResponseHeaders());
      Call call = new Call(exchange);
      try {
        checkOrigin(call);
        route(call);
      } catch (ApiException e) {
        problem(exchange, e.status, e.detail, e.retryAfter);
      } catch (RuntimeException e) {
        LOG.log(System.Logger.Level.ERROR, "request failed: {0}", e.getClass().getSimpleName());
        problem(exchange, 500, "internal error", null);
      }
    }
  }

  private void route(Call c) throws ApiException, IOException {
    String p = c.path;
    switch (p) {
      case "/healthz" -> {
        require(c, "GET");
        text(c.exchange, 200, "ok");
      }
      case "/api/v1/auth/login" -> {
        require(c, "POST");
        login(c, false);
      }
      case "/api/v1/auth/recovery" -> {
        require(c, "POST");
        login(c, true);
      }
      case "/api/v1/auth/logout" -> {
        require(c, "POST");
        logout(c);
      }
      case "/api/v1/me" -> {
        require(c, "GET");
        me(c);
      }
      case "/api/v1/me/enrollment" -> {
        require(c, "POST");
        enroll(c);
      }
      case "/api/v1/me/password" -> {
        require(c, "PUT");
        changePassword(c);
      }
      case "/api/v1/me/app-passwords" -> {
        if (c.method.equals("GET")) {
          listAppPasswords(c);
        } else {
          require(c, "POST");
          createAppPassword(c);
        }
      }
      case "/api/v1/me/recovery-code" -> {
        require(c, "POST");
        recoveryCode(c);
      }
      default -> {
        String prefix = "/api/v1/me/app-passwords/";
        if (p.startsWith(prefix) && p.length() > prefix.length()) {
          require(c, "DELETE");
          revokeAppPassword(c, p.substring(prefix.length()));
        } else {
          throw new ApiException(404, "not found");
        }
      }
    }
  }

  // ---- authentication ----

  private void login(Call c, boolean recovery) throws ApiException, IOException {
    JsonNode body = body(c);
    String username = string(body, "username", MAX_USERNAME);
    String secret = string(body, recovery ? "code" : "password", MAX_SECRET);
    boolean bearer = body.path("bearer").asBoolean(false);
    MailboxLease lease;
    try {
      lease =
          recovery
              ? auth.authenticateRecovery(username, secret, c.source())
              : auth.authenticatePrimary(username, secret, c.source());
    } catch (AuthenticationException e) {
      throw switch (e.reason()) {
        case INVALID, NOT_PERMITTED -> ApiException.unauthorized();
        case THROTTLED ->
            new ApiException(
                429,
                "too many attempts",
                e.retryAfter() == null ? Duration.ofSeconds(5) : e.retryAfter());
        case UNAVAILABLE -> new ApiException(503, "temporarily unavailable");
      };
    }
    SessionStore.Issued issued = sessions.create(lease);
    ObjectNode out = sessionView(issued.session());
    out.put("mfa", "not-configured");
    if (bearer) {
      out.put("token", issued.token());
    } else {
      c.exchange
          .getResponseHeaders()
          .add(
              "Set-Cookie",
              COOKIE
                  + "="
                  + issued.token()
                  + "; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age="
                  + settings.absoluteLifetime().toSeconds());
    }
    send(c.exchange, 200, out);
  }

  private void logout(Call c) throws ApiException, IOException {
    c.session();
    String token = c.token;
    if (token != null) {
      sessions.end(token);
    }
    clearCookie(c.exchange);
    c.exchange.sendResponseHeaders(204, -1);
  }

  private void me(Call c) throws ApiException, IOException {
    send(c.exchange, 200, sessionView(c.session()));
  }

  private ObjectNode sessionView(SessionStore.Session session) {
    ObjectNode out = json.createObjectNode();
    out.put("address", session.principal().address().toString());
    Optional<Account> account = identity.account(session.lease.mailboxId());
    out.put("state", account.map(a -> a.state().name().toLowerCase(Locale.ROOT)).orElse("unknown"));
    out.put("credential", session.principal().slotKind().name().toLowerCase(Locale.ROOT));
    ArrayNode caps = out.putArray("capabilities");
    for (Capability capability : Capability.values()) {
      if (session.principal().can(capability)) {
        caps.add(capability.name().toLowerCase(Locale.ROOT));
      }
    }
    out.put("enrollmentRequired", session.principal().can(Capability.ENROLL));
    out.put("expiresAt", sessions.expiresAt(session).toString());
    out.put("csrfToken", session.csrfToken);
    return out;
  }

  // ---- self-service ----

  private void enroll(Call c) throws ApiException, IOException {
    SessionStore.Session session = c.session();
    capability(session, Capability.ENROLL);
    JsonNode body = body(c);
    String password = string(body, "newPassword", MAX_SECRET);
    try {
      lifecycle.enroll(session.lease, password);
    } catch (Exception e) {
      throw lifecycleFailure(e);
    }
    endSession(c);
    send(c.exchange, 200, json.createObjectNode().put("reauthenticate", true));
  }

  private void changePassword(Call c) throws ApiException, IOException {
    SessionStore.Session session = c.session();
    capability(session, Capability.KEY_ADMINISTRATION);
    JsonNode body = body(c);
    stepUp(c, session, body);
    String password = string(body, "newPassword", MAX_SECRET);
    try {
      lifecycle.changePassword(session.lease, password);
    } catch (Exception e) {
      throw lifecycleFailure(e);
    }
    if (!session.lease.isValid()) {
      // A recovery code is single-use: every session of the mailbox ended.
      endSession(c);
      send(c.exchange, 200, json.createObjectNode().put("reauthenticate", true));
      return;
    }
    c.exchange.sendResponseHeaders(204, -1);
  }

  private void listAppPasswords(Call c) throws ApiException, IOException {
    SessionStore.Session session = c.session();
    capability(session, Capability.KEY_ADMINISTRATION);
    ArrayNode list = json.createArrayNode();
    for (SlotDescriptor slot : slots(session)) {
      if (slot.kind() == SlotKind.APP) {
        list.addObject()
            .put("id", slot.slotId().toString())
            .put("label", slot.label())
            .put("createdAt", slot.createdAt().toString());
      }
    }
    send(c.exchange, 200, json.createObjectNode().set("appPasswords", list));
  }

  private void createAppPassword(Call c) throws ApiException, IOException {
    SessionStore.Session session = c.session();
    capability(session, Capability.KEY_ADMINISTRATION);
    JsonNode body = body(c);
    stepUp(c, session, body);
    String label = string(body, "label", MAX_LABEL);
    if (label.isBlank()) {
      throw ApiException.badRequest("label must not be blank");
    }
    Set<OpaqueId> before = new HashSet<>();
    slots(session).forEach(s -> before.add(s.slotId()));
    ObjectNode out = json.createObjectNode();
    try (Secret password = lifecycle.createAppPassword(session.lease, label)) {
      out.put("password", new String(password.exposeCopy(), StandardCharsets.UTF_8));
    } catch (Exception e) {
      throw lifecycleFailure(e);
    }
    for (SlotDescriptor slot : slots(session)) {
      if (!before.contains(slot.slotId())) {
        out.put("id", slot.slotId().toString());
      }
    }
    out.put("label", label);
    send(c.exchange, 201, out);
  }

  private void revokeAppPassword(Call c, String rawId) throws ApiException, IOException {
    SessionStore.Session session = c.session();
    capability(session, Capability.KEY_ADMINISTRATION);
    stepUp(c, session, null);
    OpaqueId id = OpaqueId.parseOrNull(rawId);
    if (id == null
        || slots(session).stream()
            .noneMatch(s -> s.slotId().equals(id) && s.kind() == SlotKind.APP)) {
      throw new ApiException(404, "not found");
    }
    try {
      lifecycle.revokeSlot(session.lease, id);
    } catch (Exception e) {
      throw lifecycleFailure(e);
    }
    c.exchange.sendResponseHeaders(204, -1);
  }

  private void recoveryCode(Call c) throws ApiException, IOException {
    SessionStore.Session session = c.session();
    capability(session, Capability.KEY_ADMINISTRATION);
    JsonNode body = body(c);
    stepUp(c, session, body);
    ObjectNode out = json.createObjectNode();
    try (Secret code = lifecycle.createRecoveryCode(session.lease)) {
      out.put("code", new String(code.exposeCopy(), StandardCharsets.UTF_8));
    } catch (Exception e) {
      throw lifecycleFailure(e);
    }
    send(c.exchange, 201, out);
  }

  // ---- helpers ----

  /**
   * Sensitive operations need a credential check within {@link HttpSettings#stepUpWindow()}; after
   * that the request must carry {@code currentPassword}.
   */
  private void stepUp(Call c, SessionStore.Session session, @Nullable JsonNode body)
      throws ApiException {
    Instant now = clock.instant();
    if (now.isBefore(session.authenticatedAt.plus(settings.stepUpWindow()))) {
      return;
    }
    JsonNode field = body == null ? null : body.get("currentPassword");
    if (field == null || !field.isTextual()) {
      throw new ApiException(403, "recent authentication required");
    }
    try {
      if (!auth.verifyPassword(session.lease, field.asText(), c.source())) {
        throw ApiException.unauthorized();
      }
    } catch (AuthenticationException e) {
      throw e.reason() == AuthenticationException.Reason.THROTTLED
          ? new ApiException(429, "too many attempts", Duration.ofSeconds(5))
          : ApiException.unauthorized();
    }
    session.authenticatedAt = now;
  }

  private List<SlotDescriptor> slots(SessionStore.Session session) throws ApiException {
    try {
      return lifecycle.slots(session.lease);
    } catch (Exception e) {
      throw lifecycleFailure(e);
    }
  }

  private static void capability(SessionStore.Session session, Capability capability)
      throws ApiException {
    if (!session.principal().can(capability)) {
      throw ApiException.forbidden();
    }
  }

  private ApiException lifecycleFailure(Exception e) {
    return switch (e) {
      case KeyLifecycle.LifecycleException l ->
          new ApiException(409, java.util.Objects.requireNonNullElse(l.getMessage(), "conflict"));
      case KdfAdmission.Rejected r -> new ApiException(429, "server busy", Duration.ofSeconds(5));
      case SecurityException s -> ApiException.forbidden();
      case InterruptedException i -> {
        Thread.currentThread().interrupt();
        yield new ApiException(503, "temporarily unavailable");
      }
      default -> {
        LOG.log(System.Logger.Level.ERROR, "operation failed: {0}", e.getClass().getSimpleName());
        yield new ApiException(503, "temporarily unavailable");
      }
    };
  }

  private void endSession(Call c) {
    String token = c.token;
    if (token != null) {
      sessions.end(token);
    }
    if (!c.bearer) {
      clearCookie(c.exchange);
    }
  }

  /** Mutating requests from browsers must come from the configured origin. */
  private void checkOrigin(Call c) throws ApiException {
    if (c.method.equals("GET") || c.method.equals("HEAD")) {
      return;
    }
    String origin = c.exchange.getRequestHeaders().getFirst("Origin");
    if (origin != null && !origin.equals(settings.origin())) {
      throw ApiException.forbidden();
    }
    String fetchSite = c.exchange.getRequestHeaders().getFirst("Sec-Fetch-Site");
    if (fetchSite != null && fetchSite.equals("cross-site")) {
      throw ApiException.forbidden();
    }
  }

  private static void require(Call c, String method) throws ApiException {
    if (!c.method.equals(method)) {
      throw new ApiException(405, "method not allowed");
    }
  }

  private JsonNode body(Call c) throws ApiException, IOException {
    String type = c.exchange.getRequestHeaders().getFirst("Content-Type");
    if (type == null || !type.toLowerCase(Locale.ROOT).startsWith("application/json")) {
      throw new ApiException(415, "expected application/json");
    }
    byte[] bytes;
    try (InputStream in = c.exchange.getRequestBody()) {
      bytes = in.readNBytes(settings.maxBodyBytes() + 1);
    }
    try {
      if (bytes.length > settings.maxBodyBytes()) {
        throw new ApiException(413, "request body too large");
      }
      JsonNode node = json.readTree(bytes);
      if (node == null || !node.isObject()) {
        throw ApiException.badRequest("expected a JSON object");
      }
      return node;
    } catch (JsonProcessingException e) {
      throw ApiException.badRequest("malformed JSON");
    } finally {
      Arrays.fill(bytes, (byte) 0);
    }
  }

  private static String string(JsonNode body, String field, int maxLength) throws ApiException {
    JsonNode value = body.get(field);
    if (value == null || !value.isTextual()) {
      throw ApiException.badRequest(field + " is required");
    }
    String text = value.asText();
    if (text.isEmpty() || text.length() > maxLength) {
      throw ApiException.badRequest(field + " has an invalid length");
    }
    return text;
  }

  private static @Nullable String cookie(Headers headers) {
    List<String> values = headers.get("Cookie");
    if (values == null) {
      return null;
    }
    List<String> found = new ArrayList<>();
    for (String header : values) {
      for (String part : header.split(";", -1)) {
        String p = part.strip();
        if (p.startsWith(COOKIE + "=")) {
          found.add(p.substring(COOKIE.length() + 1));
        }
      }
    }
    return found.size() == 1 ? found.getFirst() : null;
  }

  private static void clearCookie(HttpExchange exchange) {
    exchange
        .getResponseHeaders()
        .add("Set-Cookie", COOKIE + "=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0");
  }

  private static void securityHeaders(Headers h) {
    h.set("Cache-Control", "no-store");
    h.set("Pragma", "no-cache");
    h.set("X-Content-Type-Options", "nosniff");
    h.set("Referrer-Policy", "no-referrer");
    h.set("X-Frame-Options", "DENY");
    h.set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
    h.set("Strict-Transport-Security", "max-age=31536000");
  }

  private void send(HttpExchange exchange, int status, JsonNode body) throws IOException {
    byte[] bytes = json.writeValueAsBytes(body);
    exchange.getResponseHeaders().set("Content-Type", "application/json");
    exchange.sendResponseHeaders(status, bytes.length);
    try (OutputStream out = exchange.getResponseBody()) {
      out.write(bytes);
    } finally {
      Arrays.fill(bytes, (byte) 0);
    }
  }

  private static void text(HttpExchange exchange, int status, String body) throws IOException {
    byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
    exchange.sendResponseHeaders(status, bytes.length);
    try (OutputStream out = exchange.getResponseBody()) {
      out.write(bytes);
    }
  }

  private void problem(HttpExchange exchange, int status, String detail, @Nullable Duration retry)
      throws IOException {
    ObjectNode body =
        json.createObjectNode()
            .put("type", "about:blank")
            .put("title", title(status))
            .put("status", status)
            .put("detail", detail);
    byte[] bytes = json.writeValueAsBytes(body);
    exchange.getResponseHeaders().set("Content-Type", "application/problem+json");
    if (retry != null) {
      exchange
          .getResponseHeaders()
          .set("Retry-After", String.valueOf(Math.max(1, retry.toSeconds())));
    }
    exchange.sendResponseHeaders(status, bytes.length);
    try (OutputStream out = exchange.getResponseBody()) {
      out.write(bytes);
    }
  }

  private static String title(int status) {
    return switch (status) {
      case 400 -> "Bad Request";
      case 401 -> "Unauthorized";
      case 403 -> "Forbidden";
      case 404 -> "Not Found";
      case 405 -> "Method Not Allowed";
      case 409 -> "Conflict";
      case 413 -> "Content Too Large";
      case 415 -> "Unsupported Media Type";
      case 429 -> "Too Many Requests";
      case 503 -> "Service Unavailable";
      default -> "Internal Server Error";
    };
  }
}
