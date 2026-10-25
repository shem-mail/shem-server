package org.shem.common;

import java.util.Arrays;

/** Immutable byte sequence for value types; never exposes its backing array. */
public final class ImmutableBytes {
  public static final ImmutableBytes EMPTY = new ImmutableBytes(new byte[0]);
  private final byte[] bytes;

  private ImmutableBytes(byte[] bytes) {
    this.bytes = bytes;
  }

  public static ImmutableBytes copyOf(byte[] bytes) {
    return bytes.length == 0 ? EMPTY : new ImmutableBytes(bytes.clone());
  }

  public int length() {
    return bytes.length;
  }

  public byte[] toByteArray() {
    return bytes.clone();
  }

  @Override
  public boolean equals(Object obj) {
    return obj instanceof ImmutableBytes other && Arrays.equals(bytes, other.bytes);
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(bytes);
  }

  @Override
  public String toString() {
    return "ImmutableBytes[" + bytes.length + "]";
  }
}
