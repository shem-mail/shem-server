package org.shem.smtp;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import org.shem.common.OpaqueId;

/**
 * Per-account recipient budget: a token bucket of {@code perHour} tokens refilled continuously. In
 * memory only; a restart grants a fresh budget. Entries exist only for accounts that have sent and
 * are dropped once refilled, so the map is bounded by recently active accounts.
 */
final class SendRate {
  private record Bucket(double tokens, Instant updated) {}

  private final int perHour;
  private final Clock clock;
  private final Map<OpaqueId, Bucket> buckets = new HashMap<>();

  SendRate(int perHour, Clock clock) {
    this.perHour = perHour;
    this.clock = clock;
  }

  /** Takes one recipient from {@code mailbox}'s budget; false if it is exhausted. */
  synchronized boolean take(OpaqueId mailbox) {
    Instant now = clock.instant();
    if (buckets.size() > 10_000) {
      buckets.values().removeIf(b -> refill(b, now) >= perHour);
    }
    Bucket bucket = buckets.get(mailbox);
    double tokens = bucket == null ? perHour : refill(bucket, now);
    if (tokens < 1) {
      buckets.put(mailbox, new Bucket(tokens, now));
      return false;
    }
    buckets.put(mailbox, new Bucket(tokens - 1, now));
    return true;
  }

  private double refill(Bucket bucket, Instant now) {
    double hours = Duration.between(bucket.updated(), now).toMillis() / 3_600_000.0;
    return Math.min(perHour, bucket.tokens() + hours * perHour);
  }
}
