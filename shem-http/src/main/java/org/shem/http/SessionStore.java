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
import org.shem.common.OpaqueId;
import org.shem.crypto.CryptoException;
import org.shem.crypto.Purpose;
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
  }

  /** A new session and the token to hand to the client (shown once). */
  record Issued(Session session, String token) {}

  private final HttpSettings settings;
  private final Clock clock;
  private final SecureRandom random;
  private final Map<String, Session> byTokenHash = new HashMap<>();
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
      evicted.forEach(s -> s.lease.close());
    }
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
        ended.lease.close();
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
      session.lease.close();
    }
  }

  /** Ends expired and revoked sessions. */
  void sweep() {
    List<Session> evicted = new ArrayList<>();
    synchronized (byTokenHash) {
      expire(evicted);
    }
    evicted.forEach(s -> s.lease.close());
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
    synchronized (byTokenHash) {
      all = new ArrayList<>(byTokenHash.values());
      byTokenHash.clear();
    }
    all.forEach(s -> s.lease.close());
    tokenKey.close();
  }
}
