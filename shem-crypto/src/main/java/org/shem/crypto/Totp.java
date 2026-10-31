package org.shem.crypto;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.OptionalLong;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * RFC 6238 TOTP with the parameters every authenticator app supports: HMAC-SHA1, 30-second steps,
 * six digits, and a 160-bit secret. Verification accepts one step of clock drift either side and
 * returns the matched step so callers can reject reuse of that step or any earlier one. The JCE
 * {@code Mac} keeps its own copy of the secret during a call.
 */
public final class Totp {
  public static final int SECRET_BYTES = 20;
  public static final long STEP_SECONDS = 30;
  static final int DIGITS = 6;
  static final int DRIFT_STEPS = 1;

  private Totp() {}

  public static Secret generateSecret(SecureRandom random) {
    return Secret.random(random, SECRET_BYTES);
  }

  /**
   * The step matched by {@code code} at {@code now}, if it is valid and later than {@code
   * lastAcceptedStep}. Comparison does not short-circuit on the first differing digit.
   */
  public static OptionalLong verify(Secret secret, String code, Instant now, long lastAcceptedStep)
      throws CryptoException {
    if (code.length() != DIGITS || !code.chars().allMatch(c -> c >= '0' && c <= '9')) {
      return OptionalLong.empty();
    }
    long current = Math.floorDiv(now.getEpochSecond(), STEP_SECONDS);
    long matched = -1;
    for (long step = current - DRIFT_STEPS; step <= current + DRIFT_STEPS; step++) {
      if (java.security.MessageDigest.isEqual(
              code.getBytes(java.nio.charset.StandardCharsets.US_ASCII),
              code(secret, step).getBytes(java.nio.charset.StandardCharsets.US_ASCII))
          && step > lastAcceptedStep) {
        matched = step;
      }
    }
    return matched < 0 ? OptionalLong.empty() : OptionalLong.of(matched);
  }

  /** The code for a given time step (RFC 4226 dynamic truncation). */
  public static String code(Secret secret, long step) throws CryptoException {
    byte[] counter = new byte[8];
    for (int i = 7; i >= 0; i--) {
      counter[i] = (byte) (step >>> (8 * (7 - i)));
    }
    byte[] hash;
    try {
      Mac mac = Mac.getInstance("HmacSHA1");
      mac.init(new SecretKeySpec(secret.bytes(), "HmacSHA1"));
      hash = mac.doFinal(counter);
    } catch (GeneralSecurityException e) {
      throw new CryptoException("TOTP computation failed", e);
    }
    int offset = hash[hash.length - 1] & 0x0f;
    int binary =
        ((hash[offset] & 0x7f) << 24)
            | ((hash[offset + 1] & 0xff) << 16)
            | ((hash[offset + 2] & 0xff) << 8)
            | (hash[offset + 3] & 0xff);
    java.util.Arrays.fill(hash, (byte) 0);
    return String.format(java.util.Locale.ROOT, "%06d", binary % 1_000_000);
  }

  /** RFC 4648 base32 without padding, the encoding authenticator apps expect. */
  public static String base32(Secret secret) {
    String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    byte[] data = secret.bytes();
    StringBuilder out = new StringBuilder();
    int buffer = 0;
    int bits = 0;
    for (byte b : data) {
      buffer = (buffer << 8) | (b & 0xff);
      bits += 8;
      while (bits >= 5) {
        out.append(alphabet.charAt((buffer >> (bits - 5)) & 31));
        bits -= 5;
      }
    }
    if (bits > 0) {
      out.append(alphabet.charAt((buffer << (5 - bits)) & 31));
    }
    return out.toString();
  }
}
