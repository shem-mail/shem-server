package org.shem.tls;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * Active ACME HTTP-01 tokens and their key authorizations, served on port 80 only while an order is
 * being validated. Key authorizations are public by design (RFC 8555 section 8.3); the map is
 * bounded and tokens are syntax-checked so the port-80 route cannot be used to probe anything else.
 */
public final class Http01Challenges {
  public static final String PATH_PREFIX = "/.well-known/acme-challenge/";
  static final int MAX_ACTIVE = 100;
  private static final Pattern TOKEN = Pattern.compile("[A-Za-z0-9_-]{1,128}");

  private final ConcurrentHashMap<String, String> active = new ConcurrentHashMap<>();

  /** Publishes a token; fails rather than growing without bound. */
  public void publish(String token, String keyAuthorization) {
    if (!TOKEN.matcher(token).matches()) {
      throw new IllegalArgumentException("invalid challenge token");
    }
    if (active.size() >= MAX_ACTIVE && !active.containsKey(token)) {
      throw new IllegalStateException("too many active challenges");
    }
    active.put(token, keyAuthorization);
  }

  public void withdraw(String token) {
    active.remove(token);
  }

  /** The key authorization for {@code token}, if it is currently published. */
  public Optional<String> lookup(String token) {
    if (!TOKEN.matcher(token).matches()) {
      return Optional.empty();
    }
    return Optional.ofNullable(active.get(token));
  }

  public int size() {
    return active.size();
  }
}
