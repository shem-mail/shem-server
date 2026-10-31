package org.shem.common;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** Bounded reader for records produced by {@link RecordWriter}. Every read checks limits. */
public final class RecordReader {
  private final byte[] data;
  private int position;

  public RecordReader(byte[] data) {
    this.data = data;
  }

  public int u8() throws FormatException {
    require(1);
    return data[position++] & 0xff;
  }

  public int u16() throws FormatException {
    require(2);
    int value = ((data[position] & 0xff) << 8) | (data[position + 1] & 0xff);
    position += 2;
    return value;
  }

  public long u32() throws FormatException {
    require(4);
    long value = 0;
    for (int i = 0; i < 4; i++) {
      value = (value << 8) | (data[position++] & 0xff);
    }
    return value;
  }

  public long i64() throws FormatException {
    require(8);
    long value = 0;
    for (int i = 0; i < 8; i++) {
      value = (value << 8) | (data[position++] & 0xff);
    }
    return value;
  }

  public boolean bool() throws FormatException {
    int value = u8();
    if (value > 1) {
      throw new FormatException("invalid boolean");
    }
    return value == 1;
  }

  public byte[] bytes(int maxLength) throws FormatException {
    long length = u32();
    if (length > maxLength) {
      throw new FormatException("field exceeds limit");
    }
    return raw((int) length);
  }

  public byte[] raw(int length) throws FormatException {
    require(length);
    byte[] value = Arrays.copyOfRange(data, position, position + length);
    position += length;
    return value;
  }

  public String string(int maxBytes) throws FormatException {
    byte[] raw = bytes(maxBytes);
    try {
      return StandardCharsets.UTF_8
          .newDecoder()
          .onMalformedInput(CodingErrorAction.REPORT)
          .onUnmappableCharacter(CodingErrorAction.REPORT)
          .decode(ByteBuffer.wrap(raw))
          .toString();
    } catch (CharacterCodingException e) {
      throw new FormatException("invalid UTF-8", e);
    }
  }

  public OpaqueId id() throws FormatException {
    return OpaqueId.fromBytes(raw(OpaqueId.BYTES));
  }

  public int remaining() {
    return data.length - position;
  }

  /** Fails unless every byte was consumed; trailing data is treated as corruption. */
  public void expectEnd() throws FormatException {
    if (position != data.length) {
      throw new FormatException("trailing data");
    }
  }

  private void require(int length) throws FormatException {
    if (length < 0 || data.length - position < length) {
      throw new FormatException("truncated record");
    }
  }
}
