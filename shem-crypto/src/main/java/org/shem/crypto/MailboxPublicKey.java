package org.shem.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;

/**
 * Public half of a mailbox keypair. Stored unencrypted in the routing directory so delivery works
 * while the mailbox is locked.
 */
public final class MailboxPublicKey {
  public static final int X25519_BYTES = 32;
  private final int keyVersion;
  private final byte[] x25519;

  public MailboxPublicKey(int keyVersion, byte[] x25519) {
    if (keyVersion < 1) {
      throw new IllegalArgumentException("key version must be positive");
    }
    if (x25519.length != X25519_BYTES) {
      throw new IllegalArgumentException("X25519 public key must be 32 bytes");
    }
    this.keyVersion = keyVersion;
    this.x25519 = x25519.clone();
  }

  public int keyVersion() {
    return keyVersion;
  }

  public byte[] toBytes() {
    return x25519.clone();
  }

  byte[] bytes() {
    return x25519;
  }

  /**
   * User-verifiable fingerprint (SHA-256 over profile, version, and key). Shown after enrollment
   * and on account recreation so users can detect key substitution.
   */
  public String fingerprint() {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      digest.update(
          ("shem/fingerprint/v1/" + CryptoProfile.PROFILE_VERSION + "/")
              .getBytes(java.nio.charset.StandardCharsets.US_ASCII));
      digest.update((byte) (keyVersion >>> 24));
      digest.update((byte) (keyVersion >>> 16));
      digest.update((byte) (keyVersion >>> 8));
      digest.update((byte) keyVersion);
      digest.update(x25519);
      return HexFormat.of().formatHex(digest.digest(), 0, 16);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 unavailable", e);
    }
  }

  @Override
  public boolean equals(Object obj) {
    return obj instanceof MailboxPublicKey other
        && keyVersion == other.keyVersion
        && MessageDigest.isEqual(x25519, other.x25519);
  }

  @Override
  public int hashCode() {
    return 31 * keyVersion + Arrays.hashCode(x25519);
  }

  @Override
  public String toString() {
    return "MailboxPublicKey[v" + keyVersion + "]";
  }
}
