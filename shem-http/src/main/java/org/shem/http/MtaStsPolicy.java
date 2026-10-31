package org.shem.http;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;

/**
 * The MTA-STS policy (RFC 8461) this server publishes for every local domain at {@code
 * https://mta-sts.<domain>/.well-known/mta-sts.txt}. The policy id announced in DNS is derived from
 * the policy text, so it changes exactly when the policy does.
 */
public record MtaStsPolicy(Mode mode, List<String> mx, Duration maxAge) {
  /** RFC 8461 policy modes. */
  public enum Mode {
    ENFORCE,
    TESTING,
    NONE
  }

  public MtaStsPolicy {
    mx = List.copyOf(mx);
    if (mx.isEmpty()) {
      throw new IllegalArgumentException("an MTA-STS policy needs at least one mx");
    }
    if (maxAge.isNegative() || maxAge.toSeconds() > 31_557_600) {
      throw new IllegalArgumentException("mtaSts.maxAge must be between 0 and one year");
    }
  }

  /** The policy file, CRLF-terminated lines as RFC 8461 section 3.2 specifies. */
  public String text() {
    StringBuilder out = new StringBuilder();
    out.append("version: STSv1\r\n");
    out.append("mode: ").append(mode.name().toLowerCase(Locale.ROOT)).append("\r\n");
    for (String host : mx) {
      out.append("mx: ").append(host).append("\r\n");
    }
    out.append("max_age: ").append(maxAge.toSeconds()).append("\r\n");
    return out.toString();
  }

  /** The {@code id} for the {@code _mta-sts} TXT record: 20 hex digits of the text's SHA-256. */
  public String id() {
    try {
      byte[] digest =
          MessageDigest.getInstance("SHA-256").digest(text().getBytes(StandardCharsets.US_ASCII));
      return HexFormat.of().formatHex(digest, 0, 10);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 unavailable", e);
    }
  }
}
