package org.shem.http;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.jspecify.annotations.Nullable;
import org.shem.common.OpaqueId;
import org.shem.crypto.CryptoException;
import org.shem.crypto.Purpose;
import org.shem.crypto.Secret;
import org.shem.crypto.SymmetricKey;
import org.shem.mailbox.MailboxLease;
import org.shem.mailbox.Principal;

/**
 * In-memory API sessions. A session is a random 256-bit token (given to the client) whose keyed
 * fingerprint, under a per-process key, is the key of a map entry holding the {@link MailboxLease};
 * the map therefore holds no usable token. Sessions end on logout, idle timeout, absolute lifetime,
 * lease revocation, or shutdown, and every end closes the lease so the mailbox locks when no other
 * session uses it. Nothing is persisted: a restart ends every session.
 */
final class SessionStore implements AutoCloseable {
  /** One live session. {@code authenticatedAt} is the last credential check (for step-up). */
  static final class Session {
    final OpaqueId id;
    final MailboxLease lease;
    final String csrfToken;
    final Instant created;
    volatile Instant authenticatedAt;
    volatile Instant lastSeen;

    /** The account has no second factor yet: only factor enrollment is allowed (ADR 0014). */
    volatile boolean needsFactor;

    /** Unconfirmed TOTP secret during enrollment; wiped when replaced, confirmed, or ended. */
    @Nullable Secret pendingTotp;

    /** One outstanding export ticket (ADR 0017), redeemable once by this session. */
    private @Nullable OpaqueId exportTicket;

    private @Nullable Instant exportTicketExpires;

    synchronized void offerExport(OpaqueId id, Instant expires) {
      exportTicket = id;
      exportTicketExpires = expires;
    }

    synchronized boolean redeemExport(OpaqueId id, Instant now) {
      Instant expires = exportTicketExpires;
      boolean ok = id.equals(exportTicket) && expires != null && now.isBefore(expires);
      if (ok) {
        exportTicket = null;
        exportTicketExpires = null;
      }
      return ok;
    }

    /** Outstanding WebAuthn registration challenge. */
    byte @Nullable [] registrationChallenge;

    Session(OpaqueId id, MailboxLease lease, String csrfToken, Instant now) {
      this.id = id;
      this.lease = lease;
      this.csrfToken = csrfToken;
      this.created = now;
      this.authenticatedAt = now;
      this.lastSeen = now;
    }

    Principal principal() {
      return lease.principal();
    }

    synchronized void replacePendingTotp(@Nullable Secret secret) {
      Secret old = pendingTotp;
      pendingTotp = secret;
      if (old != null) {
        old.close();
      }
    }

    void end() {
      replacePendingTotp(null);
      lease.close();
    }
  }

  /** A password-verified login waiting for its second factor; holds the lease briefly. */
  static final class Pending {
    final MailboxLease lease;
    final Instant expires;
    int attemptsLeft = MAX_FACTOR_ATTEMPTS;
    byte @Nullable [] webAuthnChallenge;

    Pending(MailboxLease lease, Instant expires) {
      this.lease = lease;
      this.expires = expires;
    }
  }

  static final int MAX_FACTOR_ATTEMPTS = 5;
  static final java.time.Duration PENDING_LIFETIME = java.time.Duration.ofMinutes(5);
  static final int MAX_FACTOR_FAILURES = 10;
  static final java.time.Duration FAILURE_WINDOW = java.time.Duration.ofMinutes(15);

  /** A new session and the token to hand to the client (shown once). */
  record Issued(Session session, String token) {}

  private final HttpSettings settings;
  private final Clock clock;
  private final SecureRandom random;
  private final Map<String, Session> byTokenHash = new HashMap<>();
  private final Map<String, Pending> pending = new HashMap<>();
  private final Map<OpaqueId, java.util.ArrayDeque<Instant>> factorFailures = new HashMap<>();
  private final SymmetricKey tokenKey;

  SessionStore(HttpSettings settings, Clock clock, SecureRandom random) {
    this.settings = settings;
    this.clock = clock;
    this.random = random;
    this.tokenKey = SymmetricKey.generate(random);
  }

  /** Takes ownership of {@code lease}; closes it if no session can be created. */
  Issued create(MailboxLease lease) throws ApiException {
    List<Session> evicted = new ArrayList<>();
    try {
      synchronized (byTokenHash) {
        expire(evicted);
        long forAccount =
            byTokenHash.values().stream()
                .filter(s -> s.lease.mailboxId().equals(lease.mailboxId()))
                .count();
        if (byTokenHash.size() >= settings.maxSessions()
            || forAccount >= settings.maxSessionsPerAccount()) {
          lease.close();
          throw new ApiException(429, "too many sessions");
        }
        String token = randomToken();
        Session session =
            new Session(OpaqueId.random(random), lease, randomToken(), clock.instant());
        byTokenHash.put(hash(token), session);
        return new Issued(session, token);
      }
    } finally {
      evicted.forEach(Session::end);
    }
  }

  /** Holds {@code lease} until the second factor is verified; returns the challenge id. */
  String createPending(MailboxLease lease) throws ApiException {
    List<Pending> expired = new ArrayList<>();
    try {
      synchronized (byTokenHash) {
        Instant now = clock.instant();
        pending
            .values()
            .removeIf(
                p -> {
                  if (now.isAfter(p.expires) || !p.lease.isValid()) {
                    expired.add(p);
                    return true;
                  }
                  return false;
                });
        long forAccount =
            pending.values().stream()
                .filter(p -> p.lease.mailboxId().equals(lease.mailboxId()))
                .count();
        if (pending.size() >= settings.maxSessions()
            || forAccount >= settings.maxSessionsPerAccount()) {
          lease.close();
          throw new ApiException(429, "too many pending logins");
        }
        String id = randomToken();
        pending.put(hash(id), new Pending(lease, now.plus(PENDING_LIFETIME)));
        return id;
      }
    } finally {
      expired.forEach(p -> p.lease.close());
    }
  }

  /** The live pending login for {@code id}. */
  Optional<Pending> pending(String id) {
    Pending ended = null;
    try {
      synchronized (byTokenHash) {
        Pending p = pending.get(hash(id));
        if (p == null) {
          return Optional.empty();
        }
        if (clock.instant().isAfter(p.expires) || !p.lease.isValid() || p.attemptsLeft <= 0) {
          pending.remove(hash(id));
          ended = p;
          return Optional.empty();
        }
        return Optional.of(p);
      }
    } finally {
      if (ended != null) {
        ended.lease.close();
      }
    }
  }

  /** Records a failed factor attempt; ends the pending login when its attempts are used up. */
  void factorFailed(String id, Pending p) {
    boolean end;
    synchronized (byTokenHash) {
      p.attemptsLeft--;
      end = p.attemptsLeft <= 0;
      if (end) {
        pending.remove(hash(id));
      }
      java.util.ArrayDeque<Instant> failures =
          factorFailures.computeIfAbsent(p.lease.mailboxId(), k -> new java.util.ArrayDeque<>());
      failures.addLast(clock.instant());
    }
    if (end) {
      p.lease.close();
    }
  }

  /** Whether the account had too many recent factor failures (online guessing protection). */
  boolean factorLocked(OpaqueId mailboxId) {
    synchronized (byTokenHash) {
      java.util.ArrayDeque<Instant> failures = factorFailures.get(mailboxId);
      if (failures == null) {
        return false;
      }
      Instant cutoff = clock.instant().minus(FAILURE_WINDOW);
      while (!failures.isEmpty() && failures.peekFirst().isBefore(cutoff)) {
        failures.pollFirst();
      }
      if (failures.isEmpty()) {
        factorFailures.remove(mailboxId);
        return false;
      }
      return failures.size() >= MAX_FACTOR_FAILURES;
    }
  }

  /** Turns a verified pending login into a session. */
  Issued promote(String id) throws ApiException {
    Pending p;
    synchronized (byTokenHash) {
      p = pending.remove(hash(id));
    }
    if (p == null) {
      throw ApiException.unauthorized();
    }
    return create(p.lease);
  }

  /** The live session for {@code token}, refreshing its idle timer. */
  Optional<Session> find(String token) {
    String key = hash(token);
    Session ended = null;
    try {
      synchronized (byTokenHash) {
        Session session = byTokenHash.get(key);
        if (session == null) {
          return Optional.empty();
        }
        if (!alive(session, clock.instant())) {
          byTokenHash.remove(key);
          ended = session;
          return Optional.empty();
        }
        session.lastSeen = clock.instant();
        return Optional.of(session);
      }
    } finally {
      if (ended != null) {
        ended.end();
      }
    }
  }

  /** Ends the session for {@code token}, if any. */
  void end(String token) {
    Session session;
    synchronized (byTokenHash) {
      session = byTokenHash.remove(hash(token));
    }
    if (session != null) {
      session.end();
    }
  }

  /** Ends expired and revoked sessions. */
  void sweep() {
    List<Session> evicted = new ArrayList<>();
    List<Pending> expired = new ArrayList<>();
    synchronized (byTokenHash) {
      expire(evicted);
      Instant now = clock.instant();
      pending
          .values()
          .removeIf(
              p -> {
                if (now.isAfter(p.expires) || !p.lease.isValid()) {
                  expired.add(p);
                  return true;
                }
                return false;
              });
    }
    expired.forEach(p -> p.lease.close());
    evicted.forEach(Session::end);
  }

  int size() {
    synchronized (byTokenHash) {
      return byTokenHash.size();
    }
  }

  private void expire(List<Session> evicted) {
    Instant now = clock.instant();
    byTokenHash
        .values()
        .removeIf(
            s -> {
              if (alive(s, now)) {
                return false;
              }
              evicted.add(s);
              return true;
            });
  }

  private boolean alive(Session session, Instant now) {
    return session.lease.isValid()
        && now.isBefore(session.lastSeen.plus(settings.idleTimeout()))
        && now.isBefore(session.created.plus(settings.absoluteLifetime()));
  }

  Instant expiresAt(Session session) {
    Instant idle = session.lastSeen.plus(settings.idleTimeout());
    Instant absolute = session.created.plus(settings.absoluteLifetime());
    return idle.isBefore(absolute) ? idle : absolute;
  }

  private String randomToken() {
    byte[] bytes = new byte[32];
    random.nextBytes(bytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  private String hash(String token) {
    try {
      byte[] digest =
          tokenKey.fingerprint(
              Purpose.SESSION_TOKEN, token.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
      return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    } catch (CryptoException e) {
      throw new IllegalStateException("token fingerprint failed", e);
    }
  }

  @Override
  public void close() {
    List<Session> all;
    List<Pending> waiting;
    synchronized (byTokenHash) {
      all = new ArrayList<>(byTokenHash.values());
      byTokenHash.clear();
      waiting = new ArrayList<>(pending.values());
      pending.clear();
    }
    all.forEach(Session::end);
    waiting.forEach(p -> p.lease.close());
    tokenKey.close();
  }
}
