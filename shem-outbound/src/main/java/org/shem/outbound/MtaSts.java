package org.shem.outbound;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.jspecify.annotations.Nullable;
import org.shem.policy.DnsResolver;

/**
 * MTA-STS (RFC 8461): discovers a domain's policy through {@code _mta-sts} TXT, fetches it with
 * {@link Fetcher}, and caches it in memory (bounded, capped {@code max_age}). In {@code enforce}
 * mode only matching MX hosts are used and TLS with a valid certificate for the MX name is
 * required; otherwise delivery is deferred, never downgraded. {@code testing} and {@code none}
 * policies do not change delivery (no TLS reporting is sent).
 */
final class MtaSts {
  static final Duration MAX_AGE_CAP = Duration.ofDays(365);
  static final int MAX_CACHED = 10_000;

  /** Fetches {@code https://mta-sts.<domain>/.well-known/mta-sts.txt}. */
  interface Fetcher {
    String fetch(String domain) throws IOException;
  }

  enum Mode {
    ENFORCE,
    TESTING,
    NONE
  }

  /** A parsed policy. */
  record Policy(Mode mode, List<String> mx, Duration maxAge) {
    boolean allows(String host) {
      String h = host.toLowerCase(Locale.ROOT);
      for (String pattern : mx) {
        if (pattern.startsWith("*.")) {
          String suffix = pattern.substring(1);
          int dot = h.indexOf('.');
          if (dot > 0 && h.substring(dot).equals(suffix)) {
            return true;
          }
        } else if (pattern.equals(h)) {
          return true;
        }
      }
      return false;
    }
  }

  private record Cached(String id, Policy policy, Instant expires) {}

  private final DnsResolver resolver;
  private final Fetcher fetcher;
  private final Clock clock;
  private final Map<String, Cached> cache =
      new LinkedHashMap<>(256, 0.75f, true) {
        private static final long serialVersionUID = 1L;

        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Cached> eldest) {
          return size() > MAX_CACHED;
        }
      };

  MtaSts(DnsResolver resolver, Fetcher fetcher, Clock clock) {
    this.resolver = resolver;
    this.fetcher = fetcher;
    this.clock = clock;
  }

  /**
   * The policy to apply for {@code domain}, or {@code null} when none is known. A failed refresh
   * keeps an unexpired cached policy, so an attacker who blocks discovery cannot downgrade a domain
   * that has published one before.
   */
  @Nullable Policy policy(String domain) {
    String key = domain.toLowerCase(Locale.ROOT);
    Instant now = clock.instant();
    Cached cached;
    synchronized (cache) {
      cached = cache.get(key);
      if (cached != null && now.isAfter(cached.expires())) {
        cache.remove(key);
        cached = null;
      }
    }
    String id;
    try {
      id = discoveredId(key);
    } catch (DnsResolver.DnsTemporaryException e) {
      return cached == null ? null : cached.policy();
    }
    if (id == null) {
      return cached == null ? null : cached.policy();
    }
    if (cached != null && cached.id().equals(id)) {
      return cached.policy();
    }
    Policy fetched;
    try {
      fetched = parse(fetcher.fetch(key));
    } catch (IOException e) {
      return cached == null ? null : cached.policy();
    }
    if (fetched == null) {
      return cached == null ? null : cached.policy();
    }
    Duration age = fetched.maxAge().compareTo(MAX_AGE_CAP) > 0 ? MAX_AGE_CAP : fetched.maxAge();
    synchronized (cache) {
      cache.put(key, new Cached(id, fetched, now.plus(age)));
    }
    return fetched;
  }

  private @Nullable String discoveredId(String domain) throws DnsResolver.DnsTemporaryException {
    String found = null;
    for (String record : resolver.lookup("_mta-sts." + domain, DnsResolver.Type.TXT)) {
      if (!record.startsWith("v=STSv1")) {
        continue;
      }
      if (found != null) {
        return null; // more than one record: no policy (RFC 8461 section 3.1)
      }
      for (String part : record.split(";", -1)) {
        String p = part.strip();
        if (p.startsWith("id=")) {
          found = p.substring(3);
        }
      }
      if (found == null || !found.matches("[A-Za-z0-9]{1,32}")) {
        return null;
      }
    }
    return found;
  }

  /** Parses a policy file; {@code null} if it is invalid. */
  static @Nullable Policy parse(String text) {
    String version = null;
    Mode mode = null;
    Duration maxAge = null;
    List<String> mx = new ArrayList<>();
    for (String raw : text.split("\n", -1)) {
      String line = raw.strip();
      if (line.isEmpty()) {
        continue;
      }
      int colon = line.indexOf(':');
      if (colon <= 0) {
        return null;
      }
      String key = line.substring(0, colon).strip();
      String value = line.substring(colon + 1).strip();
      switch (key) {
        case "version" -> version = value;
        case "mode" ->
            mode =
                switch (value) {
                  case "enforce" -> Mode.ENFORCE;
                  case "testing" -> Mode.TESTING;
                  case "none" -> Mode.NONE;
                  default -> null;
                };
        case "max_age" -> {
          try {
            maxAge = Duration.ofSeconds(Long.parseLong(value));
          } catch (NumberFormatException e) {
            return null;
          }
        }
        case "mx" -> mx.add(value.toLowerCase(Locale.ROOT));
        default -> {}
      }
    }
    if (!"STSv1".equals(version) || mode == null || maxAge == null || maxAge.isNegative()) {
      return null;
    }
    if (mode != Mode.NONE && mx.isEmpty()) {
      return null;
    }
    return new Policy(mode, List.copyOf(mx), maxAge);
  }
}
