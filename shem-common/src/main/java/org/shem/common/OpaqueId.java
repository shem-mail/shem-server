package org.shem.common;

import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * A random 128-bit identifier rendered as 32 lowercase hex characters.
 *
 * <p>Used for mailbox, blob, receipt, slot, and job identifiers. Never derived from content,
 * addresses, or folder names, so it is safe to use in filesystem paths.
 */
public record OpaqueId(String value) implements Comparable<OpaqueId> {
  private static final Pattern FORMAT = Pattern.compile("[0-9a-f]{32}");
  private static final HexFormat HEX = HexFormat.of();
  public static final int BYTES = 16;

  public OpaqueId {
    Objects.requireNonNull(value, "value");
    if (!FORMAT.matcher(value).matches()) {
      throw new IllegalArgumentException("malformed opaque id");
    }
  }

  public static OpaqueId random(SecureRandom random) {
    byte[] bytes = new byte[BYTES];
    random.nextBytes(bytes);
    return new OpaqueId(HEX.formatHex(bytes));
  }

  public static OpaqueId fromBytes(byte[] bytes) {
    if (bytes.length != BYTES) {
      throw new IllegalArgumentException("opaque id must be 16 bytes");
    }
    return new OpaqueId(HEX.formatHex(bytes));
  }

  /** Parses untrusted input, returning {@code null} instead of throwing on malformed values. */
  public static @org.jspecify.annotations.Nullable OpaqueId parseOrNull(String value) {
    return FORMAT.matcher(value).matches() ? new OpaqueId(value) : null;
  }

  public byte[] toBytes() {
    return HEX.parseHex(value);
  }

  /** Two-level shard prefix such as {@code aa/bd}, used to keep directories small. */
  public String shardPath() {
    return value.substring(0, 2) + "/" + value.substring(2, 4);
  }

  @Override
  public int compareTo(OpaqueId other) {
    return value.compareTo(other.value);
  }

  @Override
  public String toString() {
    return value;
  }
}
