package org.shem.http;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import org.jspecify.annotations.Nullable;
import org.shem.common.OpaqueId;
import org.shem.crypto.KdfAdmission;
import org.shem.crypto.Secret;
import org.shem.identity.Account;
import org.shem.identity.AccountState;
import org.shem.identity.AdminStore;
import org.shem.identity.Alias;
import org.shem.identity.Domain;
import org.shem.identity.EmailAddress;
import org.shem.identity.IdentityException;
import org.shem.identity.IdentityService;
import org.shem.mailbox.MailboxProvisioning;

/**
 * {@code /api/v1/admin} (ADR 0016). Administrators authenticate with their own password and a
 * mandatory TOTP code, independent of any mailbox. They manage domains, accounts, aliases, and DKIM
 * keys, but no route reads mail, exports, resets a password to recover a mailbox, or touches
 * mailbox keys. Optimistic versions: mutations carry {@code version} (PATCH) or {@code If-Match}
 * (DELETE).
 */
public final class AdminApi {
  static final String COOKIE = "__Host-shem-admin";
  static final Duration STEP_UP = Duration.ofMinutes(5);
  private static final System.Logger LOG = System.getLogger(AdminApi.class.getName());

  /** What the admin API needs from the rest of the server. */
  public record Services(
      AdminStore admins,
      IdentityService identity,
      MailboxProvisioning provisioning,
      DkimKeys dkim,
      Duration bootstrapValidity,
      String mailHost,
      java.util.function.Supplier<org.shem.tls.CertificateRenewal.Status> certificates,
      org.shem.identity.AuditLog audit) {}

  private final Api api;
  private final Services s;
  private final AdminSessionStore sessions;
  private final Clock clock;

  AdminApi(Api api, Services services, Clock clock, SecureRandom random) {
    this.api = api;
    this.s = services;
    this.sessions = new AdminSessionStore(clock, random);
    this.clock = clock;
  }

  void sweep() {
    sessions.sweep();
  }

  void close() {
    sessions.close();
  }

  /**
   * Every authenticated mutation is audited (ADR 0020): a durable {@code attempt} record before it
   * runs, refused with 503 if that record cannot be written, and the outcome after.
   */
  void route(Api.Call c) throws ApiException, IOException {
    String p = c.path.substring("/api/v1/admin".length());
    String[] parts = p.substring(1).split("/", -1);
    if (c.method.equals("GET") || p.startsWith("/auth/")) {
      dispatch(c, p, parts);
      return;
    }
    AdminSessionStore.Session session;
    try {
      session = session(c);
    } catch (ApiException e) {
      // Unauthenticated: routing answers 405 or 401 and nothing changes, so nothing to audit.
      dispatch(c, p, parts);
      return;
    }
    String actor = "admin:" + session.admin;
    String action =
        parts[0]
            + (parts.length == 3 ? "." + parts[2] : "")
            + "."
            + c.method.toLowerCase(Locale.ROOT);
    String target = parts.length >= 2 ? parts[1] : "-";
    try {
      s.audit().record(actor, action, target, "attempt");
    } catch (IOException e) {
      throw new ApiException(503, "audit log unavailable; change refused");
    }
    String outcome = "failed";
    try {
      dispatch(c, p, parts);
      outcome = "ok";
    } finally {
      String result = c.auditTarget;
      auditQuietly(actor, action, result == null ? target : result, outcome);
    }
  }

  private void auditQuietly(String actor, String action, String target, String outcome) {
    try {
      s.audit().record(actor, action, target, outcome);
    } catch (IOException e) {
      LOG.log(System.Logger.Level.ERROR, "audit record could not be written");
    }
  }

  private void dispatch(Api.Call c, String p, String[] parts) throws ApiException, IOException {
    switch (p) {
      case "/auth/login" -> {
        Api.require(c, "POST");
        login(c);
        return;
      }
      case "/auth/mfa/verify" -> {
        Api.require(c, "POST");
        verify(c);
        return;
      }
      case "/auth/logout" -> {
        Api.require(c, "POST");
        session(c);
        String token = token(c);
        if (token != null) {
          sessions.end(token);
        }
        c.exchange
            .getResponseHeaders()
            .add("Set-Cookie", COOKIE + "=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0");
        c.exchange.sendResponseHeaders(204, -1);
        return;
      }
      case "/tls" -> {
        Api.require(c, "GET");
        session(c);
        certificates(c);
        return;
      }
      case "/me" -> {
        Api.require(c, "GET");
        AdminSessionStore.Session session = session(c);
        api.send(
            c.exchange,
            200,
            api.json
                .createObjectNode()
                .put("admin", session.admin)
                .put("expiresAt", sessions.expiresAt(session).toString())
                .put("csrfToken", session.csrfToken));
        return;
      }
      case "/domains" -> {
        if (c.method.equals("GET")) {
          listDomains(c);
        } else {
          Api.require(c, "POST");
          createDomain(c);
        }
        return;
      }
      case "/accounts" -> {
        if (c.method.equals("GET")) {
          listAccounts(c);
        } else {
          Api.require(c, "POST");
          createAccount(c);
        }
        return;
      }
      case "/aliases" -> {
        if (c.method.equals("GET")) {
          listAliases(c);
        } else {
          Api.require(c, "POST");
          createAlias(c);
        }
        return;
      }
      default -> {}
    }
    if (parts.length == 2 && parts[0].equals("domains")) {
      if (c.method.equals("GET")) {
        getDomain(c, id(parts[1]));
      } else {
        Api.require(c, "DELETE");
        deleteDomain(c, id(parts[1]));
      }
    } else if (parts.length == 3
        && parts[0].equals("domains")
        && parts[2].equals("dkim-rotations")) {
      Api.require(c, "POST");
      rotateDkim(c, id(parts[1]));
    } else if (parts.length == 3 && parts[0].equals("domains") && parts[2].equals("dns")) {
      Api.require(c, "GET");
      dns(c, id(parts[1]));
    } else if (parts.length == 2 && parts[0].equals("accounts")) {
      switch (c.method) {
        case "GET" -> getAccount(c, id(parts[1]));
        case "DELETE" -> deleteAccount(c, id(parts[1]));
        default -> {
          Api.require(c, "PATCH");
          updateAccount(c, id(parts[1]));
        }
      }
    } else if (parts.length == 2 && parts[0].equals("aliases")) {
      if (c.method.equals("PATCH")) {
        updateAlias(c, id(parts[1]));
      } else {
        Api.require(c, "DELETE");
        deleteAlias(c, id(parts[1]));
      }
    } else {
      throw new ApiException(404, "not found");
    }
  }

  // ---- authentication ----

  private void login(Api.Call c) throws ApiException, IOException {
    if (sessions.blocked(c.source())) {
      throw new ApiException(429, "too many attempts", AdminSessionStore.FAILURE_WINDOW);
    }
    JsonNode body = api.body(c);
    String name = Api.string(body, "name", 64);
    String password = Api.string(body, "password", 1024);
    Optional<AdminStore.Verified> verified;
    try {
      verified = s.admins().verifyPassword(name, password);
    } catch (KdfAdmission.Rejected e) {
      throw new ApiException(429, "server busy", Duration.ofSeconds(5));
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new ApiException(503, "temporarily unavailable");
    }
    auditQuietly("admin:" + name, "auth.password", "-", verified.isPresent() ? "ok" : "failed");
    if (verified.isEmpty()) {
      sessions.failed(c.source());
      throw ApiException.unauthorized();
    }
    String challenge = sessions.createPending(verified.get());
    api.send(
        c.exchange,
        200,
        api.json.createObjectNode().put("mfaRequired", true).put("challenge", challenge));
  }

  private void verify(Api.Call c) throws ApiException, IOException {
    JsonNode body = api.body(c);
    String id = Api.string(body, "challenge", 128);
    String code = Api.string(body, "totp", 16);
    AdminSessionStore.Pending pending =
        sessions.pending(id).orElseThrow(ApiException::unauthorized);
    boolean ok;
    try {
      ok = s.admins().verifyTotp(pending.verified, code);
    } catch (org.shem.crypto.CryptoException e) {
      ok = false;
    }
    auditQuietly("admin:" + pending.verified.name(), "auth.totp", "-", ok ? "ok" : "failed");
    if (!ok) {
      sessions.pendingFailed(id, pending);
      sessions.failed(c.source());
      throw ApiException.unauthorized();
    }
    AdminSessionStore.Issued issued = sessions.promote(id);
    ObjectNode out =
        api.json
            .createObjectNode()
            .put("admin", issued.session().admin)
            .put("csrfToken", issued.session().csrfToken)
            .put("expiresAt", sessions.expiresAt(issued.session()).toString());
    if (body.path("bearer").asBoolean(false)) {
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
                  + AdminSessionStore.ABSOLUTE.toSeconds());
    }
    api.send(c.exchange, 200, out);
  }

  private @Nullable String token(Api.Call c) {
    String authorization = c.exchange.getRequestHeaders().getFirst("Authorization");
    if (authorization != null && authorization.regionMatches(true, 0, "Bearer ", 0, 7)) {
      return authorization.substring(7).strip();
    }
    return Api.cookie(c.exchange.getRequestHeaders(), COOKIE);
  }

  private AdminSessionStore.Session session(Api.Call c) throws ApiException {
    String token = token(c);
    if (token == null) {
      throw ApiException.unauthorized();
    }
    AdminSessionStore.Session session =
        sessions.find(token).orElseThrow(ApiException::unauthorized);
    boolean bearer = c.exchange.getRequestHeaders().getFirst("Authorization") != null;
    if (!bearer && !c.method.equals("GET")) {
      String csrf = c.exchange.getRequestHeaders().getFirst("X-CSRF-Token");
      if (csrf == null
          || !java.security.MessageDigest.isEqual(
              csrf.getBytes(StandardCharsets.US_ASCII),
              session.csrfToken.getBytes(StandardCharsets.US_ASCII))) {
        throw ApiException.forbidden();
      }
    }
    return session;
  }

  /** Destructive or security-relevant changes need a login within the last five minutes. */
  private void fresh(AdminSessionStore.Session session) throws ApiException {
    if (clock.instant().isAfter(session.authenticatedAt.plus(STEP_UP))) {
      throw new ApiException(403, "recent authentication required");
    }
  }

  // ---- domains ----

  private void listDomains(Api.Call c) throws ApiException, IOException {
    session(c);
    ArrayNode list = api.json.createArrayNode();
    s.identity().directory().domains().forEach(d -> list.add(view(d)));
    api.send(c.exchange, 200, api.json.createObjectNode().set("domains", list));
  }

  private void createDomain(Api.Call c) throws ApiException, IOException {
    session(c);
    String name = Api.string(api.body(c), "name", 253);
    try {
      Domain created = s.identity().createDomain(name);
      c.auditTarget = created.domainId().toString();
      api.send(c.exchange, 201, view(created));
    } catch (IdentityException e) {
      throw failure(e);
    } catch (IllegalArgumentException e) {
      throw ApiException.badRequest("invalid domain name");
    }
  }

  private void getDomain(Api.Call c, OpaqueId id) throws ApiException, IOException {
    session(c);
    api.send(
        c.exchange,
        200,
        view(
            s.identity()
                .directory()
                .domain(id)
                .orElseThrow(() -> new ApiException(404, "not found"))));
  }

  private void deleteDomain(Api.Call c, OpaqueId id) throws ApiException, IOException {
    fresh(session(c));
    try {
      s.identity().deleteDomain(id, ifMatch(c));
    } catch (IdentityException e) {
      throw failure(e);
    }
    c.exchange.sendResponseHeaders(204, -1);
  }

  private void rotateDkim(Api.Call c, OpaqueId id) throws ApiException, IOException {
    fresh(session(c));
    String selector = Api.string(api.body(c), "selector", 63);
    if (!selector.matches("[a-z0-9][a-z0-9-]{0,62}")) {
      throw ApiException.badRequest("selector must be lower-case letters, digits, and hyphens");
    }
    Domain domain =
        s.identity().directory().domain(id).orElseThrow(() -> new ApiException(404, "not found"));
    String record;
    try {
      record = s.dkim().generate(selector, domain.name());
    } catch (java.nio.file.FileAlreadyExistsException e) {
      throw new ApiException(409, "a key for this selector already exists");
    } catch (Exception e) {
      throw new ApiException(503, "temporarily unavailable");
    }
    try {
      s.identity().setDkimSelector(id, selector);
    } catch (IdentityException e) {
      throw failure(e);
    }
    api.send(
        c.exchange,
        201,
        api.json
            .createObjectNode()
            .put("type", "TXT")
            .put("name", selector + "._domainkey." + domain.name())
            .put("value", record));
  }

  private void dns(Api.Call c, OpaqueId id) throws ApiException, IOException {
    session(c);
    Domain domain =
        s.identity().directory().domain(id).orElseThrow(() -> new ApiException(404, "not found"));
    ArrayNode records = api.json.createArrayNode();
    records
        .addObject()
        .put("type", "MX")
        .put("name", domain.name())
        .put("value", "10 " + s.mailHost() + ".");
    records
        .addObject()
        .put("type", "TXT")
        .put("name", domain.name())
        .put("value", "v=spf1 mx -all");
    records
        .addObject()
        .put("type", "TXT")
        .put("name", "_dmarc." + domain.name())
        .put("value", "v=DMARC1; p=quarantine; adkim=s; aspf=s");
    MtaStsPolicy policy = api.mtaStsPolicy();
    if (policy != null) {
      records
          .addObject()
          .put("type", "CNAME")
          .put("name", "mta-sts." + domain.name())
          .put("value", s.mailHost() + ".");
      records
          .addObject()
          .put("type", "TXT")
          .put("name", "_mta-sts." + domain.name())
          .put("value", "v=STSv1; id=" + policy.id());
    }
    String selector = domain.dkimSelector();
    if (selector != null) {
      try {
        Optional<String> record = s.dkim().publishedRecord(selector, domain.name());
        record.ifPresent(
            r ->
                records
                    .addObject()
                    .put("type", "TXT")
                    .put("name", selector + "._domainkey." + domain.name())
                    .put("value", r));
      } catch (Exception e) {
        throw new ApiException(503, "temporarily unavailable");
      }
    }
    api.send(c.exchange, 200, api.json.createObjectNode().set("records", records));
  }

  /** Listener certificate and renewal state; contains no keys or CA account data. */
  private void certificates(Api.Call c) throws IOException {
    org.shem.tls.CertificateRenewal.Status status = s.certificates().get();
    ObjectNode out = api.json.createObjectNode();
    out.put("notAfter", String.valueOf(status.notAfter()));
    out.put("renewAt", String.valueOf(status.renewAt()));
    out.put("nextAttempt", status.nextAttempt().toString());
    out.put("consecutiveFailures", status.consecutiveFailures());
    out.put("lastError", status.lastError());
    out.put("lastSuccess", String.valueOf(status.lastSuccess()));
    api.send(c.exchange, 200, out);
  }

  // ---- accounts ----

  private void listAccounts(Api.Call c) throws ApiException, IOException {
    session(c);
    ArrayNode list = api.json.createArrayNode();
    s.identity().directory().accounts().forEach(a -> list.add(view(a)));
    api.send(c.exchange, 200, api.json.createObjectNode().set("accounts", list));
  }

  private void createAccount(Api.Call c) throws ApiException, IOException {
    session(c);
    JsonNode body = api.body(c);
    EmailAddress address = address(Api.string(body, "address", 320));
    long quota = body.path("quotaBytes").asLong(0);
    if (quota < 0) {
      throw ApiException.badRequest("quotaBytes must not be negative");
    }
    MailboxProvisioning.Provisioned provisioned;
    try {
      provisioned = s.provisioning().provision(address, quota, s.bootstrapValidity());
    } catch (IdentityException e) {
      throw failure(e);
    } catch (Exception e) {
      throw new ApiException(503, "temporarily unavailable");
    }
    c.auditTarget = provisioned.account().mailboxId().toString();
    ObjectNode out = view(provisioned.account());
    try (Secret bootstrap = provisioned.bootstrapPassword()) {
      // Shown once; the administrator hands it to the user, who must replace it at enrollment.
      out.put("bootstrapPassword", new String(bootstrap.exposeCopy(), StandardCharsets.UTF_8));
    }
    api.send(c.exchange, 201, out);
  }

  private void getAccount(Api.Call c, OpaqueId id) throws ApiException, IOException {
    session(c);
    api.send(
        c.exchange,
        200,
        view(s.identity().account(id).orElseThrow(() -> new ApiException(404, "not found"))));
  }

  /**
   * Starts delayed deletion: the account stops authenticating and receiving mail at once, and its
   * address cannot be recreated before the waiting period (ADR 0006). Nothing is erased here.
   */
  private void deleteAccount(Api.Call c, OpaqueId id) throws ApiException, IOException {
    fresh(session(c));
    Account account;
    try {
      account = s.identity().changeState(id, ifMatch(c), AccountState.DELETION_PENDING);
    } catch (IdentityException e) {
      throw failure(e);
    } catch (IllegalStateException e) {
      throw new ApiException(409, "state transition not allowed");
    }
    api.send(c.exchange, 200, view(account));
  }

  private void updateAccount(Api.Call c, OpaqueId id) throws ApiException, IOException {
    AdminSessionStore.Session session = session(c);
    JsonNode body = api.body(c);
    if (!body.has("version") || !body.get("version").canConvertToLong()) {
      throw ApiException.badRequest("version is required");
    }
    long version = body.get("version").asLong();
    Account account;
    try {
      account = s.identity().account(id).orElseThrow(() -> new ApiException(404, "not found"));
      if (account.version() != version) {
        throw new ApiException(412, "version mismatch");
      }
      if (body.hasNonNull("quotaBytes")) {
        long quota = body.get("quotaBytes").asLong(-1);
        if (quota < 0) {
          throw ApiException.badRequest("quotaBytes must not be negative");
        }
        account = s.identity().changeQuota(id, account.version(), quota);
      }
      if (body.hasNonNull("state")) {
        AccountState next =
            switch (Api.string(body, "state", 32)) {
              case "active" -> AccountState.ACTIVE;
              case "blocked" -> AccountState.BLOCKED;
              case "deletion_pending" -> AccountState.DELETION_PENDING;
              default ->
                  throw ApiException.badRequest(
                      "state must be active, blocked, or deletion_pending");
            };
        if (next == AccountState.DELETION_PENDING) {
          fresh(session);
        }
        // The mailbox registry observes the change and locks the mailbox, ending its sessions.
        account = s.identity().changeState(id, account.version(), next);
      }
    } catch (IdentityException e) {
      throw failure(e);
    } catch (IllegalStateException e) {
      throw new ApiException(409, "state transition not allowed");
    }
    api.send(c.exchange, 200, view(account));
  }

  // ---- aliases ----

  private void listAliases(Api.Call c) throws ApiException, IOException {
    session(c);
    ArrayNode list = api.json.createArrayNode();
    s.identity().directory().aliases().forEach(a -> list.add(view(a)));
    api.send(c.exchange, 200, api.json.createObjectNode().set("aliases", list));
  }

  private void createAlias(Api.Call c) throws ApiException, IOException {
    session(c);
    JsonNode body = api.body(c);
    EmailAddress address = address(Api.string(body, "address", 320));
    List<EmailAddress> targets = addresses(body, "targets");
    List<OpaqueId> senders = senders(body);
    try {
      Alias created = s.identity().createAlias(address, targets, senders);
      c.auditTarget = created.aliasId().toString();
      api.send(c.exchange, 201, view(created));
    } catch (IdentityException e) {
      throw failure(e);
    }
  }

  /** Replaces an alias's targets and senders; the address itself is immutable. */
  private void updateAlias(Api.Call c, OpaqueId id) throws ApiException, IOException {
    session(c);
    JsonNode body = api.body(c);
    if (!body.has("version") || !body.get("version").canConvertToLong()) {
      throw ApiException.badRequest("version is required");
    }
    List<EmailAddress> targets = addresses(body, "targets");
    List<OpaqueId> senders = senders(body);
    try {
      api.send(
          c.exchange,
          200,
          view(s.identity().updateAlias(id, body.get("version").asLong(), targets, senders)));
    } catch (IdentityException e) {
      throw failure(e);
    }
  }

  private List<OpaqueId> senders(JsonNode body) throws ApiException {
    List<OpaqueId> senders = new ArrayList<>();
    for (EmailAddress sender : addresses(body, "senders")) {
      senders.add(
          s.identity()
              .directory()
              .accountByAddress(sender)
              .orElseThrow(() -> ApiException.badRequest("senders must be existing accounts"))
              .mailboxId());
    }
    return senders;
  }

  private void deleteAlias(Api.Call c, OpaqueId id) throws ApiException, IOException {
    session(c);
    try {
      s.identity().deleteAlias(id, ifMatch(c));
    } catch (IdentityException e) {
      throw failure(e);
    }
    c.exchange.sendResponseHeaders(204, -1);
  }

  // ---- views and helpers ----

  private ObjectNode view(Domain d) {
    ObjectNode out =
        api.json
            .createObjectNode()
            .put("id", d.domainId().toString())
            .put("name", d.name())
            .put("createdAt", d.createdAt().toString())
            .put("version", d.version());
    out.put("dkimSelector", d.dkimSelector());
    return out;
  }

  private ObjectNode view(Account a) {
    ObjectNode out =
        api.json
            .createObjectNode()
            .put("id", a.mailboxId().toString())
            .put("address", a.address().toString())
            .put("state", a.state().name().toLowerCase(Locale.ROOT))
            .put("quotaBytes", a.quotaBytes())
            .put("keyFingerprint", a.publicKey().fingerprint())
            .put("createdAt", a.createdAt().toString())
            .put("version", a.version());
    if (a.bootstrapExpiresAt() != null) {
      out.put("bootstrapExpiresAt", String.valueOf(a.bootstrapExpiresAt()));
    }
    return out;
  }

  private ObjectNode view(Alias a) {
    ObjectNode out =
        api.json
            .createObjectNode()
            .put("id", a.aliasId().toString())
            .put("address", a.address().toString())
            .put("version", a.version());
    ArrayNode targets = out.putArray("targets");
    a.targets().forEach(t -> targets.add(t.toString()));
    ArrayNode senders = out.putArray("senders");
    for (OpaqueId sender : a.senders()) {
      s.identity().account(sender).ifPresent(acct -> senders.add(acct.address().toString()));
    }
    return out;
  }

  private static EmailAddress address(String value) throws ApiException {
    try {
      return EmailAddress.parse(value);
    } catch (IllegalArgumentException e) {
      throw ApiException.badRequest("invalid address");
    }
  }

  private static List<EmailAddress> addresses(JsonNode body, String field) throws ApiException {
    JsonNode array = body.get(field);
    List<EmailAddress> out = new ArrayList<>();
    if (array == null) {
      return out;
    }
    if (!array.isArray() || array.size() > Alias.MAX_TARGETS) {
      throw ApiException.badRequest(field + " must be a list of addresses");
    }
    for (JsonNode item : array) {
      if (!item.isTextual()) {
        throw ApiException.badRequest(field + " must be a list of addresses");
      }
      out.add(address(item.asText()));
    }
    return out;
  }

  private static OpaqueId id(String raw) throws ApiException {
    OpaqueId id = OpaqueId.parseOrNull(raw);
    if (id == null) {
      throw new ApiException(404, "not found");
    }
    return id;
  }

  private static long ifMatch(Api.Call c) throws ApiException {
    String header = c.exchange.getRequestHeaders().getFirst("If-Match");
    if (header == null) {
      throw new ApiException(428, "If-Match with the current version is required");
    }
    try {
      return Long.parseLong(header.replace("\"", "").strip());
    } catch (NumberFormatException e) {
      throw ApiException.badRequest("If-Match must be a version number");
    }
  }

  private static ApiException failure(IdentityException e) {
    return switch (e.reason()) {
      case NOT_FOUND -> new ApiException(404, "not found");
      case CONFLICT -> new ApiException(409, "conflict with existing data");
      case VERSION_MISMATCH -> new ApiException(412, "version mismatch");
      case INVALID -> new ApiException(400, "invalid request");
      case ALIAS_CYCLE -> new ApiException(400, "alias would create a cycle");
      case STORAGE -> new ApiException(503, "temporarily unavailable");
    };
  }
}
