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
import org.shem.identity.AccountState;
import org.shem.identity.IdentityException;
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
  static final Duration EXPORT_TICKET = Duration.ofMinutes(5);
  static final int MAX_EXPORTS = 2;

  private final HttpSettings settings;
  private final SessionStore sessions;
  private final SessionService auth;
  private final KeyLifecycle lifecycle;
  private final IdentityService identity;
  private final Clock clock;
  private final WebAuthn webAuthn;
  private final @Nullable AdminApi admin;
  private final java.security.SecureRandom random;
  private final Jobs jobs;
  private final org.shem.common.ImmutableBytes openApi = loadOpenApi();
  private final java.util.concurrent.Semaphore exports =
      new java.util.concurrent.Semaphore(MAX_EXPORTS);
  final ObjectMapper json =
      new ObjectMapper()
          .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
          .enable(DeserializationFeature.FAIL_ON_READING_DUP_TREE_KEY);

  Api(
      HttpSettings settings,
      SessionStore sessions,
      SessionService auth,
      KeyLifecycle lifecycle,
      IdentityService identity,
      Clock clock,
      java.security.SecureRandom random,
      AdminApi.@Nullable Services adminServices) {
    this.webAuthn = new WebAuthn(settings.origin());
    this.admin = adminServices == null ? null : new AdminApi(this, adminServices, clock, random);
    this.random = random;
    this.jobs = new Jobs(clock, random);
    this.settings = settings;
    this.sessions = sessions;
    this.auth = auth;
    this.lifecycle = lifecycle;
    this.identity = identity;
    this.clock = clock;
  }

  /**
   * Expires admin sessions, challenges, and old jobs; mailbox sessions are swept by their store.
   */
  void sweep() {
    jobs.sweep();
    AdminApi admin = this.admin;
    if (admin != null) {
      admin.sweep();
    }
  }

  /** Stops background jobs and ends every admin session. */
  void close() {
    jobs.close();
    AdminApi admin = this.admin;
    if (admin != null) {
      admin.close();
    }
  }

  /** The published contract, {@code openapi.json} next to this class. */
  static org.shem.common.ImmutableBytes loadOpenApi() {
    try (InputStream in = Api.class.getResourceAsStream("openapi.json")) {
      if (in == null) {
        throw new IllegalStateException("openapi.json missing from the build");
      }
      return org.shem.common.ImmutableBytes.copyOf(in.readAllBytes());
    } catch (IOException e) {
      throw new java.io.UncheckedIOException(e);
    }
  }

  /** One request's context. */
  final class Call {
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
      return session(false);
    }

    /** {@code factorEnrollment}: also allowed for sessions that must first register a factor. */
    SessionStore.Session session(boolean factorEnrollment) throws ApiException {
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
      if (session.needsFactor && !factorEnrollment) {
        throw new ApiException(403, "second factor enrollment required");
      }
      return session;
    }
  }

  @Override
  public void handle(HttpExchange exchange) throws IOException {
    boolean aborted = false;
    try {
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
    } catch (AbortedResponse e) {
      aborted = true;
      throw e;
    } finally {
      if (!aborted) {
        exchange.close();
      }
    }
  }

  /**
   * A streamed response failed after its headers were sent. Propagating it without closing the
   * exchange makes the server drop the connection, so the client sees a broken transfer rather than
   * a cleanly terminated (and silently truncated) body.
   */
  static final class AbortedResponse extends IOException {
    private static final long serialVersionUID = 1L;

    AbortedResponse() {
      super("response aborted");
    }
  }

  private void route(Call c) throws ApiException, IOException {
    String p = c.path;
    if (p.equals("/.well-known/mta-sts.txt")) {
      require(c, "GET");
      mtaSts(c);
      return;
    }
    if (p.startsWith("/api/v1/admin/")) {
      AdminApi admin = this.admin;
      if (admin == null) {
        throw new ApiException(404, "not found");
      }
      admin.route(c);
      return;
    }
    switch (p) {
      case "/healthz" -> {
        require(c, "GET");
        text(c.exchange, 200, "ok");
      }
      case "/api/v1/openapi.json" -> {
        require(c, "GET");
        c.exchange.getResponseHeaders().set("Content-Type", "application/json");
        c.exchange.sendResponseHeaders(200, openApi.length());
        try (OutputStream out = c.exchange.getResponseBody()) {
          out.write(openApi.toByteArray());
        }
      }
      case "/api/v1/auth/login" -> {
        require(c, "POST");
        login(c, false);
      }
      case "/api/v1/auth/recovery" -> {
        require(c, "POST");
        login(c, true);
      }
      case "/api/v1/auth/mfa/webauthn-options" -> {
        require(c, "POST");
        loginWebAuthnOptions(c);
      }
      case "/api/v1/auth/mfa/verify" -> {
        require(c, "POST");
        verifyFactor(c);
      }
      case "/api/v1/me/mfa" -> {
        require(c, "GET");
        listFactors(c);
      }
      case "/api/v1/me/mfa/totp" -> {
        require(c, "POST");
        startTotp(c);
      }
      case "/api/v1/me/mfa/totp/confirm" -> {
        require(c, "POST");
        confirmTotp(c);
      }
      case "/api/v1/me/mfa/webauthn/options" -> {
        require(c, "POST");
        webAuthnRegistrationOptions(c);
      }
      case "/api/v1/me/mfa/webauthn" -> {
        require(c, "POST");
        registerWebAuthn(c);
      }
      case "/api/v1/auth/logout" -> {
        require(c, "POST");
        logout(c);
      }
      case "/api/v1/me" -> {
        if (c.method.equals("DELETE")) {
          deleteMe(c);
        } else {
          require(c, "GET");
          me(c);
        }
      }
      case "/api/v1/me/exports" -> {
        require(c, "POST");
        startExport(c);
      }
      case "/api/v1/me/key-rotations" -> {
        require(c, "POST");
        startRotation(c);
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
        String factors = "/api/v1/me/mfa/";
        String exportPrefix = "/api/v1/me/exports/";
        String jobPrefix = "/api/v1/jobs/";
        if (p.startsWith(exportPrefix) && p.endsWith("/content")) {
          require(c, "GET");
          streamExport(c, p.substring(exportPrefix.length(), p.length() - "/content".length()));
        } else if (p.startsWith(jobPrefix) && p.length() > jobPrefix.length()) {
          require(c, "GET");
          job(c, p.substring(jobPrefix.length()));
        } else if (p.startsWith(prefix) && p.length() > prefix.length()) {
          require(c, "DELETE");
          revokeAppPassword(c, p.substring(prefix.length()));
        } else if (p.startsWith(factors) && p.length() > factors.length()) {
          require(c, "DELETE");
          removeFactor(c, p.substring(factors.length()));
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
    if (!recovery && lease.principal().slotKind() == SlotKind.PASSWORD) {
      List<KeyLifecycle.FactorInfo> factors;
      try {
        factors = lifecycle.factors(lease);
      } catch (Exception e) {
        lease.close();
        throw lifecycleFailure(e);
      }
      if (!factors.isEmpty()) {
        if (sessions.factorLocked(lease.mailboxId())) {
          lease.close();
          throw new ApiException(429, "too many attempts", SessionStore.FAILURE_WINDOW);
        }
        String challenge = sessions.createPending(lease);
        ObjectNode out =
            json.createObjectNode().put("mfaRequired", true).put("challenge", challenge);
        ArrayNode methods = out.putArray("methods");
        factors.stream()
            .map(f -> f.kind().name().toLowerCase(Locale.ROOT))
            .distinct()
            .forEach(methods::add);
        send(c.exchange, 200, out);
        return;
      }
      SessionStore.Issued issued = sessions.create(lease);
      issued.session().needsFactor = true;
      issue(c, issued, bearer);
      return;
    }
    issue(c, sessions.create(lease), bearer);
  }

  /** Sends a new session to the client as a cookie or, for bearer clients, in the body. */
  private void issue(Call c, SessionStore.Issued issued, boolean bearer) throws IOException {
    ObjectNode out = sessionView(issued.session());
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
    c.session(true);
    String token = c.token;
    if (token != null) {
      sessions.end(token);
    }
    clearCookie(c.exchange);
    c.exchange.sendResponseHeaders(204, -1);
  }

  private void me(Call c) throws ApiException, IOException {
    send(c.exchange, 200, sessionView(c.session(true)));
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
    out.put("mfaEnrollmentRequired", session.needsFactor);
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

  // ---- MTA-STS policy hosting (ADR 0018) ----

  /**
   * Serves the policy only on {@code mta-sts.<domain>} for a local domain. The listener certificate
   * must cover that name (configured in {@code tls.hostNames}), or senders reject the policy fetch,
   * which is the safe failure.
   */
  private void mtaSts(Call c) throws ApiException, IOException {
    MtaStsPolicy policy = settings.mtaSts();
    String host = c.exchange.getRequestHeaders().getFirst("Host");
    if (policy == null || host == null) {
      throw new ApiException(404, "not found");
    }
    String name = host.strip().toLowerCase(Locale.ROOT);
    int colon = name.lastIndexOf(':');
    if (colon > 0) {
      name = name.substring(0, colon);
    }
    if (!name.startsWith("mta-sts.") || !identity.isLocalDomain(name.substring(8))) {
      throw new ApiException(404, "not found");
    }
    text(c.exchange, 200, policy.text());
  }

  @Nullable MtaStsPolicy mtaStsPolicy() {
    return settings.mtaSts();
  }

  // ---- account deletion, exports, and jobs (ADR 0017) ----

  /**
   * Starts delayed deletion of the caller's own account. Needs a full session (not a recovery
   * session) and a recent credential check; every session of the mailbox ends.
   */
  private void deleteMe(Call c) throws ApiException, IOException {
    SessionStore.Session session = c.session();
    capability(session, Capability.MAIL_ACCESS);
    capability(session, Capability.KEY_ADMINISTRATION);
    stepUp(c, session, optionalBody(c));
    OpaqueId mailboxId = session.lease.mailboxId();
    Account account = identity.account(mailboxId).orElseThrow(ApiException::unauthorized);
    try {
      identity.changeState(mailboxId, account.version(), AccountState.DELETION_PENDING);
    } catch (IdentityException e) {
      throw e.reason() == IdentityException.Reason.VERSION_MISMATCH
          ? new ApiException(409, "account changed concurrently; retry")
          : new ApiException(503, "temporarily unavailable");
    } catch (IllegalStateException e) {
      throw new ApiException(409, "state transition not allowed");
    }
    endSession(c);
    send(
        c.exchange,
        200,
        json.createObjectNode()
            .put("state", "deletion_pending")
            .put(
                "note",
                "Mail is no longer accepted and every session has ended. Backups and copies"
                    + " made before now are not erased by this request."));
  }

  /**
   * Negotiates an export: returns a ticket the same session redeems once, within {@link
   * #EXPORT_TICKET}, at {@code GET /me/exports/{id}/content}.
   */
  private void startExport(Call c) throws ApiException, IOException {
    SessionStore.Session session = c.session();
    capability(session, Capability.MAIL_ACCESS);
    JsonNode body = body(c);
    stepUp(c, session, body);
    String format = string(body, "format", 64);
    if (!format.equals(org.shem.mailbox.MailboxExport.FORMAT)) {
      throw ApiException.badRequest(
          "format must be "
              + org.shem.mailbox.MailboxExport.FORMAT
              + " (encrypted exports are not"
              + " yet available)");
    }
    OpaqueId id = OpaqueId.random(random);
    Instant expires = clock.instant().plus(EXPORT_TICKET);
    session.offerExport(id, expires);
    send(
        c.exchange,
        201,
        json.createObjectNode()
            .put("id", id.toString())
            .put("format", format)
            .put("expiresAt", expires.toString())
            .put("content", "/api/v1/me/exports/" + id + "/content"));
  }

  /**
   * Streams the export. Nothing is staged: a disconnect or a revoked session aborts the stream,
   * which the client sees as a truncated ZIP without a central directory.
   */
  private void streamExport(Call c, String rawId) throws ApiException, IOException {
    SessionStore.Session session = c.session();
    capability(session, Capability.MAIL_ACCESS);
    OpaqueId id = OpaqueId.parseOrNull(rawId);
    if (id == null || !session.redeemExport(id, clock.instant())) {
      throw new ApiException(404, "not found");
    }
    if (!exports.tryAcquire()) {
      throw new ApiException(429, "too many exports in progress", Duration.ofSeconds(30));
    }
    try (MailboxLease lease = session.lease.child()) {
      c.exchange.getResponseHeaders().set("Content-Type", "application/zip");
      c.exchange
          .getResponseHeaders()
          .set("Content-Disposition", "attachment; filename=\"mailbox-export.zip\"");
      c.exchange.sendResponseHeaders(200, 0);
      OutputStream out = c.exchange.getResponseBody();
      try {
        org.shem.mailbox.MailboxExport.write(lease, out, clock.instant());
        out.close();
      } catch (IOException | org.shem.store.StorageException | RuntimeException e) {
        // Headers are sent; the only honest signal left is to abort the stream unfinished.
        LOG.log(System.Logger.Level.INFO, "export aborted: {0}", e.getClass().getSimpleName());
        throw new AbortedResponse();
      }
    } finally {
      exports.release();
    }
  }

  /** Starts a key rotation job (ADR 0017); always re-proves the current password. */
  private void startRotation(Call c) throws ApiException, IOException {
    SessionStore.Session session = c.session();
    capability(session, Capability.KEY_ADMINISTRATION);
    capability(session, Capability.MAIL_ACCESS);
    JsonNode body = body(c);
    String password = string(body, "currentPassword", MAX_SECRET);
    try {
      if (!auth.verifyPassword(session.lease, password, c.source())) {
        throw ApiException.unauthorized();
      }
    } catch (AuthenticationException e) {
      throw e.reason() == AuthenticationException.Reason.THROTTLED
          ? new ApiException(429, "too many attempts", Duration.ofSeconds(5))
          : ApiException.unauthorized();
    }
    session.authenticatedAt = clock.instant();
    String key = c.exchange.getRequestHeaders().getFirst("Idempotency-Key");
    if (key != null && (key.isEmpty() || key.length() > 128)) {
      throw ApiException.badRequest("Idempotency-Key must be 1-128 characters");
    }
    MailboxLease parent = session.lease;
    Jobs.Job job;
    try {
      job =
          jobs.start(
              parent.mailboxId(),
              "key-rotation",
              key,
              j -> {
                try (MailboxLease lease = parent.child()) {
                  lifecycle.rotateKeys(lease, password);
                } catch (KeyLifecycle.LifecycleException e) {
                  j.detail = e.getMessage();
                  throw e;
                }
              });
    } catch (Jobs.Busy e) {
      throw new ApiException(409, java.util.Objects.requireNonNullElse(e.getMessage(), "busy"));
    }
    c.exchange.getResponseHeaders().set("Location", "/api/v1/jobs/" + job.id);
    send(c.exchange, 202, jobView(job));
  }

  private void job(Call c, String rawId) throws ApiException, IOException {
    SessionStore.Session session = c.session();
    OpaqueId id = OpaqueId.parseOrNull(rawId);
    Jobs.Job job =
        (id == null ? Optional.<Jobs.Job>empty() : jobs.find(id, session.lease.mailboxId()))
            .orElseThrow(() -> new ApiException(404, "not found"));
    send(c.exchange, 200, jobView(job));
  }

  private ObjectNode jobView(Jobs.Job job) {
    ObjectNode out =
        json.createObjectNode()
            .put("id", job.id.toString())
            .put("type", job.type)
            .put("status", job.status.name().toLowerCase(Locale.ROOT))
            .put("createdAt", job.created.toString());
    Instant finished = job.finished;
    if (finished != null) {
      out.put("finishedAt", finished.toString());
    }
    String detail = job.detail;
    if (detail != null) {
      out.put("detail", detail);
    }
    return out;
  }

  /** A DELETE may carry {@code currentPassword} for step-up, or no body at all. */
  private @Nullable JsonNode optionalBody(Call c) throws ApiException, IOException {
    String length = c.exchange.getRequestHeaders().getFirst("Content-Length");
    String type = c.exchange.getRequestHeaders().getFirst("Content-Type");
    if ((length == null || length.equals("0")) && type == null) {
      return null;
    }
    return body(c);
  }

  // ---- second factors (ADR 0014) ----

  private void loginWebAuthnOptions(Call c) throws ApiException, IOException {
    JsonNode body = body(c);
    String id = string(body, "challenge", 128);
    SessionStore.Pending pending = sessions.pending(id).orElseThrow(ApiException::unauthorized);
    byte[] challenge = randomBytes();
    pending.webAuthnChallenge = challenge;
    ObjectNode out = json.createObjectNode();
    out.put("challenge", b64(challenge));
    out.put("rpId", webAuthn.rpId());
    out.put("timeout", SessionStore.PENDING_LIFETIME.toMillis());
    out.put("userVerification", "preferred");
    ArrayNode allow = out.putArray("allowCredentials");
    for (byte[] credentialId : credentialIds(pending.lease)) {
      allow.addObject().put("type", "public-key").put("id", b64(credentialId));
    }
    send(c.exchange, 200, out);
  }

  private void verifyFactor(Call c) throws ApiException, IOException {
    JsonNode body = body(c);
    String id = string(body, "challenge", 128);
    SessionStore.Pending pending = sessions.pending(id).orElseThrow(ApiException::unauthorized);
    if (sessions.factorLocked(pending.lease.mailboxId())) {
      throw new ApiException(429, "too many attempts", SessionStore.FAILURE_WINDOW);
    }
    boolean ok;
    try {
      if (body.hasNonNull("totp")) {
        ok = lifecycle.verifyTotp(pending.lease, string(body, "totp", 16));
      } else if (body.has("webauthn") && body.get("webauthn").isObject()) {
        ok = verifyAssertion(pending, body.get("webauthn"));
      } else {
        throw ApiException.badRequest("totp or webauthn is required");
      }
    } catch (ApiException e) {
      throw e;
    } catch (Exception e) {
      throw lifecycleFailure(e);
    }
    if (!ok) {
      sessions.factorFailed(id, pending);
      throw ApiException.unauthorized();
    }
    issue(c, sessions.promote(id), body.path("bearer").asBoolean(false));
  }

  private boolean verifyAssertion(SessionStore.Pending pending, JsonNode assertion)
      throws Exception {
    byte[] challenge = pending.webAuthnChallenge;
    if (challenge == null) {
      return false;
    }
    pending.webAuthnChallenge = null;
    byte[] credentialId = b64field(assertion, "credentialId");
    byte[] authenticatorData = b64field(assertion, "authenticatorData");
    byte[] clientData = b64field(assertion, "clientDataJSON");
    byte[] signature = b64field(assertion, "signature");
    byte[] userHandle =
        assertion.hasNonNull("userHandle") ? b64field(assertion, "userHandle") : null;
    List<org.shem.crypto.MfaFactor> credentials = lifecycle.webAuthnCredentials(pending.lease);
    try {
      for (org.shem.crypto.MfaFactor factor : credentials) {
        byte[] material = factor.material().exposeCopy();
        Long counter;
        try {
          counter =
              webAuthn.authenticate(
                  challenge,
                  material,
                  factor.counter(),
                  credentialId,
                  userHandle,
                  authenticatorData,
                  clientData,
                  signature);
        } finally {
          Arrays.fill(material, (byte) 0);
        }
        if (counter != null) {
          return lifecycle.recordWebAuthnUse(pending.lease, factor.id(), counter);
        }
      }
      return false;
    } finally {
      credentials.forEach(org.shem.crypto.MfaFactor::close);
    }
  }

  private void listFactors(Call c) throws ApiException, IOException {
    SessionStore.Session session = c.session(true);
    ArrayNode list = json.createArrayNode();
    try {
      for (KeyLifecycle.FactorInfo f : lifecycle.factors(session.lease)) {
        list.addObject()
            .put("id", f.id().toString())
            .put("type", f.kind().name().toLowerCase(Locale.ROOT))
            .put("label", f.label())
            .put("createdAt", f.createdAt().toString());
      }
    } catch (Exception e) {
      throw lifecycleFailure(e);
    }
    send(c.exchange, 200, json.createObjectNode().set("factors", list));
  }

  private void startTotp(Call c) throws ApiException, IOException {
    SessionStore.Session session = c.session(true);
    capability(session, Capability.KEY_ADMINISTRATION);
    stepUp(c, session, body(c));
    org.shem.crypto.Secret secret = org.shem.crypto.Totp.generateSecret(random);
    String encoded = org.shem.crypto.Totp.base32(secret);
    session.replacePendingTotp(secret);
    String account = session.principal().address().toString();
    String uri =
        "otpauth://totp/Shem:"
            + java.net.URLEncoder.encode(account, StandardCharsets.UTF_8)
            + "?secret="
            + encoded
            + "&issuer=Shem&algorithm=SHA1&digits=6&period=30";
    send(c.exchange, 200, json.createObjectNode().put("secret", encoded).put("uri", uri));
  }

  private void confirmTotp(Call c) throws ApiException, IOException {
    SessionStore.Session session = c.session(true);
    capability(session, Capability.KEY_ADMINISTRATION);
    JsonNode body = body(c);
    String code = string(body, "code", 16);
    String label =
        body.hasNonNull("label") ? string(body, "label", MAX_LABEL) : "authenticator app";
    org.shem.crypto.MfaFactor factor;
    synchronized (session) {
      org.shem.crypto.Secret pending = session.pendingTotp;
      if (pending == null) {
        throw new ApiException(409, "no TOTP enrollment in progress");
      }
      java.util.OptionalLong step;
      try {
        step = org.shem.crypto.Totp.verify(pending, code, clock.instant(), 0);
      } catch (org.shem.crypto.CryptoException e) {
        throw lifecycleFailure(e);
      }
      if (step.isEmpty()) {
        throw new ApiException(400, "code does not match");
      }
      factor =
          new org.shem.crypto.MfaFactor(
              OpaqueId.random(random),
              org.shem.crypto.MfaFactor.Kind.TOTP,
              label,
              clock.instant(),
              step.getAsLong(),
              pending.copy());
      session.replacePendingTotp(null);
    }
    addFactor(c, session, factor);
  }

  private void webAuthnRegistrationOptions(Call c) throws ApiException, IOException {
    SessionStore.Session session = c.session(true);
    capability(session, Capability.KEY_ADMINISTRATION);
    stepUp(c, session, body(c));
    byte[] challenge = randomBytes();
    synchronized (session) {
      session.registrationChallenge = challenge;
    }
    ObjectNode out = json.createObjectNode();
    out.put("challenge", b64(challenge));
    out.putObject("rp").put("id", webAuthn.rpId()).put("name", "Shem");
    String address = session.principal().address().toString();
    out.putObject("user")
        .put("id", b64(session.lease.mailboxId().toString().getBytes(StandardCharsets.US_ASCII)))
        .put("name", address)
        .put("displayName", address);
    ArrayNode params = out.putArray("pubKeyCredParams");
    for (int alg : new int[] {-7, -8, -257}) {
      params.addObject().put("type", "public-key").put("alg", alg);
    }
    out.put("timeout", 300_000);
    out.put("attestation", "none");
    out.putObject("authenticatorSelection")
        .put("userVerification", "preferred")
        .put("residentKey", "discouraged");
    ArrayNode exclude = out.putArray("excludeCredentials");
    for (byte[] id : credentialIds(session.lease)) {
      exclude.addObject().put("type", "public-key").put("id", b64(id));
    }
    send(c.exchange, 200, out);
  }

  private void registerWebAuthn(Call c) throws ApiException, IOException {
    SessionStore.Session session = c.session(true);
    capability(session, Capability.KEY_ADMINISTRATION);
    JsonNode body = body(c);
    byte[] challenge;
    synchronized (session) {
      challenge = session.registrationChallenge;
      session.registrationChallenge = null;
    }
    if (challenge == null) {
      throw new ApiException(409, "no WebAuthn registration in progress");
    }
    String label = body.hasNonNull("label") ? string(body, "label", MAX_LABEL) : "security key";
    WebAuthn.Registered registered;
    try {
      registered =
          webAuthn.register(
              challenge, b64field(body, "attestationObject"), b64field(body, "clientDataJSON"));
    } catch (IllegalArgumentException e) {
      throw ApiException.badRequest("registration could not be verified");
    }
    for (byte[] existing : credentialIds(session.lease)) {
      if (Arrays.equals(existing, registered.credentialId().toByteArray())) {
        throw new ApiException(409, "authenticator already registered");
      }
    }
    addFactor(
        c,
        session,
        new org.shem.crypto.MfaFactor(
            OpaqueId.random(random),
            org.shem.crypto.MfaFactor.Kind.WEBAUTHN,
            label,
            clock.instant(),
            registered.counter(),
            org.shem.crypto.Secret.wrap(registered.material().toByteArray())));
  }

  private void addFactor(Call c, SessionStore.Session session, org.shem.crypto.MfaFactor factor)
      throws ApiException, IOException {
    String id = factor.id().toString();
    try {
      lifecycle.addFactor(session.lease, factor);
    } catch (Exception e) {
      throw lifecycleFailure(e);
    }
    if (session.needsFactor) {
      // Registering the first factor completes this session's login.
      session.needsFactor = false;
      session.authenticatedAt = clock.instant();
    }
    send(c.exchange, 201, json.createObjectNode().put("id", id));
  }

  private void removeFactor(Call c, String rawId) throws ApiException, IOException {
    SessionStore.Session session = c.session(true);
    capability(session, Capability.KEY_ADMINISTRATION);
    stepUp(c, session, null);
    OpaqueId id = OpaqueId.parseOrNull(rawId);
    if (id == null) {
      throw new ApiException(404, "not found");
    }
    try {
      lifecycle.removeFactor(session.lease, id);
    } catch (KeyLifecycle.LifecycleException e) {
      throw "no such factor".equals(e.getMessage())
          ? new ApiException(404, "not found")
          : new ApiException(409, java.util.Objects.requireNonNullElse(e.getMessage(), "conflict"));
    } catch (Exception e) {
      throw lifecycleFailure(e);
    }
    c.exchange.sendResponseHeaders(204, -1);
  }

  private List<byte[]> credentialIds(MailboxLease lease) throws ApiException {
    List<org.shem.crypto.MfaFactor> credentials;
    try {
      credentials = lifecycle.webAuthnCredentials(lease);
    } catch (Exception e) {
      throw lifecycleFailure(e);
    }
    try {
      List<byte[]> ids = new ArrayList<>();
      for (org.shem.crypto.MfaFactor factor : credentials) {
        byte[] material = factor.material().exposeCopy();
        try {
          ids.add(webAuthn.credentialId(material));
        } finally {
          Arrays.fill(material, (byte) 0);
        }
      }
      return ids;
    } finally {
      credentials.forEach(org.shem.crypto.MfaFactor::close);
    }
  }

  byte[] randomBytes() {
    byte[] bytes = new byte[32];
    random.nextBytes(bytes);
    return bytes;
  }

  static String b64(byte[] bytes) {
    return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  static byte[] b64field(JsonNode node, String field) throws ApiException {
    String value = string(node, field, 64 * 1024);
    try {
      return java.util.Base64.getUrlDecoder().decode(value);
    } catch (IllegalArgumentException e) {
      throw ApiException.badRequest(field + " is not base64url");
    }
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

  static void require(Call c, String method) throws ApiException {
    if (!c.method.equals(method)) {
      throw new ApiException(405, "method not allowed");
    }
  }

  JsonNode body(Call c) throws ApiException, IOException {
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

  static String string(JsonNode body, String field, int maxLength) throws ApiException {
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

  static @Nullable String cookie(Headers headers) {
    return cookie(headers, COOKIE);
  }

  static @Nullable String cookie(Headers headers, String name) {
    List<String> values = headers.get("Cookie");
    if (values == null) {
      return null;
    }
    List<String> found = new ArrayList<>();
    for (String header : values) {
      for (String part : header.split(";", -1)) {
        String p = part.strip();
        if (p.startsWith(name + "=")) {
          found.add(p.substring(name.length() + 1));
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

  void send(HttpExchange exchange, int status, JsonNode body) throws IOException {
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
      case 412 -> "Precondition Failed";
      case 428 -> "Precondition Required";
      case 415 -> "Unsupported Media Type";
      case 429 -> "Too Many Requests";
      case 503 -> "Service Unavailable";
      default -> "Internal Server Error";
    };
  }
}
