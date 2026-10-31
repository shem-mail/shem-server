package org.shem.mailbox;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Per-source failed-authentication budget shared by IMAP, submission, and HTTP. After {@code
 * freeFailures} failures within the window, a source is blocked for an exponentially increasing
 * period. Only sources are throttled, never accounts, so attackers cannot lock users out. State is
 * in memory only, bounded by {@code maxSources} with least-recently-used eviction.
 */
public final class AttemptLimiter {
  /** Limits configuration. */
  public record Policy(
      int freeFailures, Duration window, Duration baseBlock, Duration maxBlock, int maxSources) {
    public static final Policy DEFAULT =
        new Policy(
            5, Duration.ofMinutes(15), Duration.ofSeconds(5), Duration.ofMinutes(30), 100_000);
  }

  private final Clock clock;
  private final Policy policy;
  private final Map<String, Entry> entries;

  public AttemptLimiter(Clock clock, Policy policy) {
    this.clock = clock;
    this.policy = policy;
    this.entries =
        new LinkedHashMap<>(1024, 0.75f, true) {
          private static final long serialVersionUID = 1L;

          @Override
          protected boolean removeEldestEntry(Map.Entry<String, AttemptLimiter.Entry> eldest) {
            return size() > policy.maxSources();
          }
        };
  }

  /** Returns the remaining block time if {@code source} is currently blocked. */
  public synchronized Optional<Duration> blockedFor(InetAddress source) {
    Entry entry = entries.get(key(source));
    Instant now = clock.instant();
    if (entry == null || entry.blockedUntil == null || !now.isBefore(entry.blockedUntil)) {
      return Optional.empty();
    }
    return Optional.of(Duration.between(now, entry.blockedUntil));
  }

  public synchronized void recordFailure(InetAddress source) {
    Instant now = clock.instant();
    Entry entry = entries.computeIfAbsent(key(source), k -> new Entry());
    if (entry.windowStart == null || now.isAfter(entry.windowStart.plus(policy.window()))) {
      entry.windowStart = now;
      entry.failures = 0;
    }
    entry.failures++;
    int excess = entry.failures - policy.freeFailures();
    if (excess > 0) {
      long multiplier = 1L << Math.min(excess - 1, 20);
      Duration block = policy.baseBlock().multipliedBy(multiplier);
      if (block.compareTo(policy.maxBlock()) > 0) {
        block = policy.maxBlock();
      }
      entry.blockedUntil = now.plus(block);
    }
  }

  synchronized int trackedSources() {
    return entries.size();
  }

  /** IPv4 per address, IPv6 per /64, IPv4-mapped IPv6 treated as IPv4. */
  static String key(InetAddress address) {
    byte[] bytes = address.getAddress();
    if (address instanceof Inet6Address && isV4Mapped(bytes)) {
      try {
        return InetAddress.getByAddress(java.util.Arrays.copyOfRange(bytes, 12, 16))
            .getHostAddress();
      } catch (UnknownHostException e) {
        throw new IllegalStateException(e);
      }
    }
    if (address instanceof Inet4Address) {
      return address.getHostAddress();
    }
    StringBuilder sb = new StringBuilder("v6:");
    for (int i = 0; i < 8; i++) {
      sb.append(String.format("%02x", bytes[i]));
    }
    return sb.toString();
  }

  private static boolean isV4Mapped(byte[] bytes) {
    for (int i = 0; i < 10; i++) {
      if (bytes[i] != 0) {
        return false;
      }
    }
    return bytes[10] == (byte) 0xff && bytes[11] == (byte) 0xff;
  }

  private static final class Entry {
    @org.jspecify.annotations.Nullable Instant windowStart;
    int failures;
    @org.jspecify.annotations.Nullable Instant blockedUntil;
  }
}
