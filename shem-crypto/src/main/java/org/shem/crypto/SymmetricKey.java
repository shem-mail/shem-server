package org.shem.crypto;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadConfig2026;
import com.google.crypto.tink.aead.AesGcmKey;
import com.google.crypto.tink.subtle.Hkdf;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import org.shem.common.RecordWriter;

/**
 * A 256-bit symmetric key with record encryption (AES-256-GCM, random nonce) and purpose-bound HKDF
 * derivation. Closing wipes Shem's copy; Tink primitives created from it hold their own.
 */
public final class SymmetricKey implements AutoCloseable {
  private final Secret key;

  private SymmetricKey(Secret key) {
    if (key.length() != CryptoProfile.SYMMETRIC_KEY_BYTES) {
      key.close();
      throw new IllegalArgumentException("symmetric keys are 32 bytes");
    }
    this.key = key;
  }

  public static SymmetricKey generate(SecureRandom random) {
    return new SymmetricKey(Secret.random(random, CryptoProfile.SYMMETRIC_KEY_BYTES));
  }

  /** Takes ownership of {@code secret}. */
  public static SymmetricKey of(Secret secret) {
    return new SymmetricKey(secret);
  }

  /**
   * Derives an independent subkey for {@code purpose} and a context such as a segment id. Distinct
   * (purpose, context) pairs give independent keys, which keeps per-key nonce counts small.
   */
  public SymmetricKey derive(Purpose purpose, byte[] context) throws CryptoException {
    byte[] info =
        new RecordWriter()
            .string("shem/hkdf/v1")
            .string(purpose.label())
            .bytes(context)
            .toByteArray();
    try {
      return new SymmetricKey(
          Secret.wrap(
              Hkdf.computeHkdf(
                  "HMACSHA256",
                  key.bytes(),
                  new byte[0],
                  info,
                  CryptoProfile.SYMMETRIC_KEY_BYTES)));
    } catch (GeneralSecurityException e) {
      throw new CryptoException("key derivation failed", e);
    }
  }

  /**
   * Keyed 128-bit fingerprint (HMAC-SHA256 over the purpose label and data, truncated) for
   * pseudonymous in-memory lookup keys. The JCE {@code Mac} keeps its own unwipeable copy of the
   * key for the duration of the call.
   */
  public byte[] fingerprint(Purpose purpose, byte[] data) throws CryptoException {
    try {
      javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
      mac.init(new javax.crypto.spec.SecretKeySpec(key.bytes(), "HmacSHA256"));
      mac.update(
          new RecordWriter().string("shem/fingerprint/v1").string(purpose.label()).toByteArray());
      mac.update(data);
      return java.util.Arrays.copyOf(mac.doFinal(), 16);
    } catch (GeneralSecurityException e) {
      throw new CryptoException("fingerprint failed", e);
    }
  }

  /** Encrypts a record. Output: 12-byte nonce, ciphertext, 16-byte tag. */
  public byte[] seal(byte[] plaintext, AssociatedData context) throws CryptoException {
    try {
      return aead().encrypt(plaintext, context.bytes());
    } catch (GeneralSecurityException e) {
      throw new CryptoException("record encryption failed", e);
    }
  }

  public Secret open(byte[] ciphertext, AssociatedData context) throws CryptoException {
    try {
      return Secret.wrap(aead().decrypt(ciphertext, context.bytes()));
    } catch (GeneralSecurityException e) {
      throw new CryptoException("record authentication failed", e);
    }
  }

  /** Seals another secret (key wrapping). */
  public byte[] wrap(Secret secret, AssociatedData context) throws CryptoException {
    return seal(secret.bytes(), context);
  }

  /** Wraps another symmetric key under this key. */
  public byte[] wrapKey(SymmetricKey other, AssociatedData context) throws CryptoException {
    return seal(other.secret().bytes(), context);
  }

  public SymmetricKey unwrapKey(byte[] wrapped, AssociatedData context) throws CryptoException {
    Secret secret = open(wrapped, context);
    try {
      return SymmetricKey.of(secret);
    } catch (IllegalArgumentException e) {
      throw new CryptoException("wrapped value is not a symmetric key", e);
    }
  }

  public StreamingCipher streaming(int segmentBytes) throws CryptoException {
    return StreamingCipher.create(key, segmentBytes);
  }

  public SymmetricKey copy() {
    return new SymmetricKey(key.copy());
  }

  Secret secret() {
    return key;
  }

  /** Copy of the raw key for nesting inside another encrypted record; caller wipes it. */
  public Secret exportSecret() {
    return key.copy();
  }

  @AccessesPartialKey
  private Aead aead() throws GeneralSecurityException {
    AesGcmKey gcmKey =
        AesGcmKey.builder()
            .setParameters(CryptoProfile.aesGcm())
            .setKeyBytes(SecretBytes.copyFrom(key.bytes(), InsecureSecretKeyAccess.get()))
            .build();
    return KeysetHandle.newBuilder()
        .addEntry(KeysetHandle.importKey(gcmKey).withRandomId().makePrimary())
        .build()
        .getPrimitive(AeadConfig2026.get(), Aead.class);
  }

  @Override
  public void close() {
    key.close();
  }

  @Override
  public String toString() {
    return "SymmetricKey[redacted]";
  }
}
