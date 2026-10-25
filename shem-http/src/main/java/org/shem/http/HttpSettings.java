package org.shem.http;

import java.net.InetSocketAddress;
import java.time.Duration;

/**
 * HTTP listener and session limits.
 *
 * @param origin the only browser origin allowed to make mutating cookie-authenticated requests, for
 *     example {@code https://mail.example.org}
 * @param stepUpWindow how long after login sensitive operations need no password re-entry
 */
public record HttpSettings(
    InetSocketAddress bind,
    String origin,
    int maxConcurrentRequests,
    int maxBodyBytes,
    int maxSessions,
    int maxSessionsPerAccount,
    Duration idleTimeout,
    Duration absoluteLifetime,
    Duration stepUpWindow) {
  public HttpSettings {
    if (maxConcurrentRequests <= 0 || maxBodyBytes <= 0 || maxSessions <= 0) {
      throw new IllegalArgumentException("invalid HTTP limits");
    }
    if (maxSessionsPerAccount <= 0 || idleTimeout.isNegative() || absoluteLifetime.isNegative()) {
      throw new IllegalArgumentException("invalid HTTP limits");
    }
  }
}
