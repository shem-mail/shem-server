package org.shem.crypto;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.streamingaead.AesGcmHkdfStreamingKey;
import com.google.crypto.tink.streamingaead.StreamingAeadConfig2026;
import com.google.crypto.tink.util.SecretBytes;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.SeekableByteChannel;
import java.security.GeneralSecurityException;

/**
 * Segmented authenticated encryption for message blobs and index files (Tink AES-256-GCM-HKDF
 * streaming). Each stream derives a fresh key from a random salt, segments carry their index and a
 * final-segment flag, so truncation, extension, and reordering fail authentication. Associated data
 * binds mailbox, object id, and purpose against cross-file substitution.
 *
 * <p>Decrypting streams throw {@link IOException} on authentication failure at the failing segment;
 * callers must not treat data already returned from a failed stream as trusted.
 */
public final class StreamingCipher {
  private final StreamingAead aead;

  private StreamingCipher(StreamingAead aead) {
    this.aead = aead;
  }

  @AccessesPartialKey
  static StreamingCipher create(Secret key, int segmentBytes) throws CryptoException {
    try {
      AesGcmHkdfStreamingKey streamingKey =
          AesGcmHkdfStreamingKey.create(
              CryptoProfile.streaming(segmentBytes),
              SecretBytes.copyFrom(key.bytes(), InsecureSecretKeyAccess.get()));
      return new StreamingCipher(
          KeysetHandle.newBuilder()
              .addEntry(KeysetHandle.importKey(streamingKey).withRandomId().makePrimary())
              .build()
              .getPrimitive(StreamingAeadConfig2026.get(), StreamingAead.class));
    } catch (GeneralSecurityException e) {
      throw new CryptoException("streaming cipher setup failed", e);
    }
  }

  public OutputStream encrypt(OutputStream ciphertext, AssociatedData context)
      throws CryptoException, IOException {
    try {
      return aead.newEncryptingStream(ciphertext, context.bytes());
    } catch (GeneralSecurityException e) {
      throw new CryptoException("stream encryption failed", e);
    }
  }

  public InputStream decrypt(InputStream ciphertext, AssociatedData context)
      throws CryptoException, IOException {
    try {
      return aead.newDecryptingStream(ciphertext, context.bytes());
    } catch (GeneralSecurityException e) {
      throw new CryptoException("stream decryption failed", e);
    }
  }

  /**
   * Random-access decryption; {@code size()} of the result is the plaintext length. The first
   * segment is read and authenticated eagerly because Tink's keyset-level channel selects the key
   * (and therefore knows the size) only after a successful read.
   */
  public SeekableByteChannel decryptSeekable(SeekableByteChannel ciphertext, AssociatedData context)
      throws CryptoException, IOException {
    try {
      SeekableByteChannel channel = aead.newSeekableDecryptingChannel(ciphertext, context.bytes());
      try {
        channel.read(java.nio.ByteBuffer.allocate(1));
        channel.position(0);
      } catch (IOException e) {
        channel.close();
        throw e;
      }
      return channel;
    } catch (GeneralSecurityException e) {
      throw new CryptoException("stream decryption failed", e);
    }
  }
}
