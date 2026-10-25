package org.shem.common;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Builds a compact big-endian binary record with length-prefixed fields.
 *
 * <p>The encoding is canonical: the same field sequence always produces the same bytes, which makes
 * it suitable for associated data. Call {@link #toByteArrayAndWipe()} when the record holds
 * secrets.
 */
public final class RecordWriter {
  private final ByteArrayOutputStream out = new ByteArrayOutputStream(128);

  public RecordWriter u8(int value) {
    if (value < 0 || value > 0xff) {
      throw new IllegalArgumentException("u8 out of range");
    }
    out.write(value);
    return this;
  }

  public RecordWriter u16(int value) {
    if (value < 0 || value > 0xffff) {
      throw new IllegalArgumentException("u16 out of range");
    }
    out.write(value >>> 8);
    out.write(value);
    return this;
  }

  public RecordWriter u32(long value) {
    if (value < 0 || value > 0xffffffffL) {
      throw new IllegalArgumentException("u32 out of range");
    }
    for (int shift = 24; shift >= 0; shift -= 8) {
      out.write((int) (value >>> shift));
    }
    return this;
  }

  public RecordWriter i64(long value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
      out.write((int) (value >>> shift));
    }
    return this;
  }

  public RecordWriter bool(boolean value) {
    return u8(value ? 1 : 0);
  }

  /** Writes a u32 length followed by the bytes. */
  public RecordWriter bytes(byte[] value) {
    u32(value.length);
    out.write(value, 0, value.length);
    return this;
  }

  /** Writes the bytes without a length prefix; the reader must know the size. */
  public RecordWriter raw(byte[] value) {
    out.write(value, 0, value.length);
    return this;
  }

  public RecordWriter string(String value) {
    return bytes(value.getBytes(StandardCharsets.UTF_8));
  }

  public RecordWriter id(OpaqueId id) {
    return raw(id.toBytes());
  }

  public int size() {
    return out.size();
  }

  public byte[] toByteArray() {
    return out.toByteArray();
  }

  /**
   * Returns the record and overwrites the internal buffer. {@link ByteArrayOutputStream} may
   * already have left copies behind while growing; this is best effort, not guaranteed erasure.
   */
  public byte[] toByteArrayAndWipe() {
    byte[] result = out.toByteArray();
    byte[] zeros = new byte[out.size()];
    out.reset();
    out.write(zeros, 0, zeros.length);
    out.reset();
    Arrays.fill(zeros, (byte) 0);
    return result;
  }
}
