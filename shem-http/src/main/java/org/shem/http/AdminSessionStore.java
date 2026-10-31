package org.shem.http;

import java.net.InetAddress;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.shem.crypto.CryptoException;
import org.shem.crypto.Purpose;
import org.shem.crypto.SymmetricKey;
import org.shem.identity.AdminStore;

/**
 * In-memory administrator sessions (ADR 0016), separate from mailbox sessions: they hold no mailbox
 * lease and grant no mailbox access. Tokens are stored as keyed fingerprints. A password-verified
 * login waits as a pending challenge (holding the admin key only until its TOTP code is checked).
 * Failed admin logins are limited per client address.
 */
final class AdminSessionStore implements AutoCloseable {
  static final Duration IDLE = Duration.ofMinutes(15);
  static final Duration ABSOLUTE = Duration.ofHours(8);
  static final Duration PENDING = Duration.ofMinutes(5);
  static final int MAX_SESSIONS = 64;
  static final int MAX_ATTEMPTS = 5;
  static final int MAX_FAILURES = 10;
  static final Duration FAILURE_WINDOW = Duration.ofMinutes(15);

  static final class Session {
    final String admin;
    final String csrfToken;
    final Instant created;
    volatile Instant lastSeen;
    volatile Instant authenticatedAt;

    Session(String admin, String csrfToken, Instant now) {
      this.admin = admin;
      this.csrfToken = csrfToken;
      this.created = now;
      this.lastSeen = now;
      this.authenticatedAt = now;
    }
  }

  static final class Pending {
    final AdminStore.Verified verified;
    final Instant expires;
    int attemptsLeft = MAX_ATTEMPTS;

    Pending(AdminStore.Verified verified, Instant expires) {
      this.verified = verified;
      this.expires = expires;
    }
  }

  record Issued(Session session, String token) {}

  private final Clock clock;
  private final SecureRandom random;
  private final SymmetricKey tokenKey;
  private final Map<String, Session> sessions = new HashMap<>();
  private final Map<String, Pending> pending = new HashMap<>();
  private final Map<InetAddress, ArrayDeque<Instant>> failures = new HashMap<>();

  AdminSessionStore(Clock clock, SecureRandom random) {
    this.clock = clock;
    this.random = random;
    this.tokenKey = SymmetricKey.generate(random);
  }

  synchronized boolean blocked(InetAddress source) {
    ArrayDeque<Instant> list = failures.get(source);
    if (list == null) {
      return false;
    }
    Instant cutoff = clock.instant().minus(FAILURE_WINDOW);
    while (!list.isEmpty() && list.peekFirst().isBefore(cutoff)) {
      list.pollFirst();
    }
    if (list.isEmpty()) {
      failures.remove(source);
      return false;
    }
    return list.size() >= MAX_FAILURES;
  }

  synchronized void failed(InetAddress source) {
    if (failures.size() > 10_000) {
      failures.clear();
    }
    failures.computeIfAbsent(source, k -> new ArrayDeque<>()).addLast(clock.instant());
  }

  /** Takes ownership of {@code verified}. */
  synchronized String createPending(AdminStore.Verified verified) throws ApiException {
    expirePending();
    if (pending.size() >= MAX_SESSIONS) {
      verified.close();
      throw new ApiException(429, "too many pending logins");
    }
    String id = randomToken();
    pending.put(hash(id), new Pending(verified, clock.instant().plus(PENDING)));
    return id;
  }

  synchronized Optional<Pending> pending(String id) {
    expirePending();
    return Optional.ofNullable(pending.get(hash(id)));
  }

  /** A failed TOTP attempt; the pending login ends when its attempts are used up. */
  synchronized void pendingFailed(String id, Pending p) {
    p.attemptsLeft--;
    if (p.attemptsLeft <= 0) {
      pending.remove(hash(id));
      p.verified.close();
    }
  }

  synchronized Issued promote(String id) throws ApiException {
    Pending p = pending.remove(hash(id));
    if (p == null) {
      throw ApiException.unauthorized();
    }
    try {
      expireSessions();
      if (sessions.size() >= MAX_SESSIONS) {
        throw new ApiException(429, "too many sessions");
      }
      String token = randomToken();
      Session session = new Session(p.verified.name(), randomToken(), clock.instant());
      sessions.put(hash(token), session);
      return new Issued(session, token);
    } finally {
      p.verified.close();
    }
  }

  synchronized Optional<Session> find(String token) {
    expireSessions();
    Session session = sessions.get(hash(token));
    if (session != null) {
      session.lastSeen = clock.instant();
    }
    return Optional.ofNullable(session);
  }

  synchronized void end(String token) {
    sessions.remove(hash(token));
  }

  /** Ends the sessions of a deleted administrator. */
  synchronized void endAll(String admin) {
    sessions.values().removeIf(s -> s.admin.equals(admin));
  }

  synchronized void sweep() {
    expireSessions();
    expirePending();
  }

  Instant expiresAt(Session s) {
    Instant idle = s.lastSeen.plus(IDLE);
    Instant absolute = s.created.plus(ABSOLUTE);
    return idle.isBefore(absolute) ? idle : absolute;
  }

  private void expireSessions() {
    Instant now = clock.instant();
    sessions.values().removeIf(s -> !now.isBefore(expiresAt(s)));
  }

  private void expirePending() {
    Instant now = clock.instant();
    List<Pending> expired = new ArrayList<>();
    pending
        .values()
        .removeIf(
            p -> {
              if (now.isAfter(p.expires)) {
                expired.add(p);
                return true;
              }
              return false;
            });
    expired.forEach(p -> p.verified.close());
  }

  private String randomToken() {
    byte[] bytes = new byte[32];
    random.nextBytes(bytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  private String hash(String token) {
    try {
      return Base64.getUrlEncoder()
          .withoutPadding()
          .encodeToString(
              tokenKey.fingerprint(
                  Purpose.SESSION_TOKEN,
                  ("admin:" + token).getBytes(java.nio.charset.StandardCharsets.US_ASCII)));
    } catch (CryptoException e) {
      throw new IllegalStateException("token fingerprint failed", e);
    }
  }

  @Override
  public synchronized void close() {
    sessions.clear();
    pending.values().forEach(p -> p.verified.close());
    pending.clear();
    tokenKey.close();
  }
}
