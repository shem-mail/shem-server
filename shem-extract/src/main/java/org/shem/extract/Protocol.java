package org.shem.extract;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * The parent/worker wire format over the worker's stdin/stdout (ADR 0019). Every field is
 * length-checked; nothing here is persisted.
 *
 * <pre>
 * handshake  parent: MAGIC, probePort:int, canaryPath:str, scratch:str
 *            worker: MAGIC, networkReachable:bool, canaryReadable:bool, tmpdir:str, tmpfs:bool
 * request    parent: 1, contentType:str, extension:str, maxChars:int, length:int, bytes
 * response   worker: status:byte, truncated:bool, length:int, utf8 bytes
 * </pre>
 */
final class Protocol {
  static final int MAGIC = 0x53485831; // "SHX1"
  static final byte REQUEST = 1;
  static final int MAX_STRING = 4096;

  static final byte TEXT = 0;
  static final byte UNSUPPORTED = 1;
  static final byte ENCRYPTED = 2;
  static final byte LIMIT = 3;
  static final byte FAILED = 4;

  private Protocol() {}

  static void writeString(DataOutputStream out, String value) throws IOException {
    byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
    if (bytes.length > MAX_STRING) {
      throw new IOException("protocol string too long");
    }
    out.writeShort(bytes.length);
    out.write(bytes);
  }

  static String readString(DataInputStream in) throws IOException {
    int length = in.readUnsignedShort();
    if (length > MAX_STRING) {
      throw new IOException("protocol string too long");
    }
    byte[] bytes = new byte[length];
    in.readFully(bytes);
    return new String(bytes, StandardCharsets.UTF_8);
  }

  static byte[] readBytes(DataInputStream in, int limit) throws IOException {
    int length = in.readInt();
    if (length < 0 || length > limit) {
      throw new IOException("protocol payload out of bounds");
    }
    byte[] bytes = new byte[length];
    in.readFully(bytes);
    return bytes;
  }

  static void expectMagic(DataInputStream in) throws IOException {
    int magic;
    try {
      magic = in.readInt();
    } catch (EOFException e) {
      throw new IOException("worker ended before the handshake", e);
    }
    if (magic != MAGIC) {
      throw new IOException("protocol mismatch");
    }
  }
}
