package org.shem.crypto;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Owned, wipeable secret bytes (credentials, symmetric keys, decrypted key material).
 *
 * <p>{@link #close()} overwrites the buffer. This is best effort: the JVM, libraries (Tink, Bouncy
 * Castle, JCE providers) and protocol stacks may hold further copies that cannot be erased, and
 * strings received from protocol libraries are immutable. Never log or serialize a Secret except
 * through the explicit methods below.
 */
public final class Secret implements AutoCloseable {
  private final byte[] bytes;
  private boolean closed;

  private Secret(byte[] bytes) {
    this.bytes = bytes;
  }

  /** Takes ownership of {@code bytes}; the caller must not use the array afterwards. */
  public static Secret wrap(byte[] bytes) {
    return new Secret(bytes);
  }

  public static Secret copyOf(byte[] bytes) {
    return new Secret(bytes.clone());
  }

  public static Secret random(SecureRandom random, int length) {
    byte[] bytes = new byte[length];
    random.nextBytes(bytes);
    return new Secret(bytes);
  }

  /** Encodes a credential as UTF-8; the source characters remain the caller's responsibility. */
  // The encoder allocates the buffer itself; the whole backing array is wiped deliberately.
  @SuppressWarnings("ByteBufferBackingArray")
  public static Secret utf8(CharSequence chars) {
    ByteBuffer encoded;
    try {
      encoded =
          StandardCharsets.UTF_8
              .newEncoder()
              .onMalformedInput(CodingErrorAction.REPORT)
              .onUnmappableCharacter(CodingErrorAction.REPORT)
              .encode(CharBuffer.wrap(chars));
    } catch (CharacterCodingException e) {
      throw new IllegalArgumentException("credential is not valid Unicode", e);
    }
    byte[] result = new byte[encoded.remaining()];
    encoded.get(result);
    if (encoded.hasArray()) {
      Arrays.fill(encoded.array(), (byte) 0);
    }
    return new Secret(result);
  }

  public int length() {
    checkOpen();
    return bytes.length;
  }

  /** Internal view for this package's primitives; never escapes the crypto module. */
  byte[] bytes() {
    checkOpen();
    return bytes;
  }

  /**
   * Returns a copy the caller owns and must wipe, for the few places that must hand a secret to a
   * client exactly once (for example a newly generated app password).
   */
  public byte[] exposeCopy() {
    checkOpen();
    return bytes.clone();
  }

  public Secret copy() {
    return copyOf(bytes());
  }

  public boolean isClosed() {
    return closed;
  }

  /** Constant-time comparison. */
  public boolean contentEquals(Secret other) {
    return java.security.MessageDigest.isEqual(bytes(), other.bytes());
  }

  @Override
  public void close() {
    if (!closed) {
      Arrays.fill(bytes, (byte) 0);
      closed = true;
    }
  }

  private void checkOpen() {
    if (closed) {
      throw new IllegalStateException("secret already closed");
    }
  }

  @Override
  public String toString() {
    return "Secret[redacted]";
  }
}
