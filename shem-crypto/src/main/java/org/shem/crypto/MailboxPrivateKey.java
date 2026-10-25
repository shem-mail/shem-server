package org.shem.crypto;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.hybrid.HpkePrivateKey;
import com.google.crypto.tink.hybrid.HpkePublicKey;
import com.google.crypto.tink.hybrid.HybridConfig2026;
import com.google.crypto.tink.subtle.X25519;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;

/**
 * Unlocked private half of a mailbox keypair. Exists only in memory under an unlock lease.
 *
 * <p>Tink keeps its own copy of the key inside {@link SecretBytes}, which cannot be wiped; {@link
 * #close()} wipes Shem's copy and makes this object unusable.
 */
public final class MailboxPrivateKey implements AutoCloseable {
  private final MailboxPublicKey publicKey;
  private final Secret privateBytes;
  private final HybridDecrypt decrypt;

  private MailboxPrivateKey(
      MailboxPublicKey publicKey, Secret privateBytes, HybridDecrypt decrypt) {
    this.publicKey = publicKey;
    this.privateBytes = privateBytes;
    this.decrypt = decrypt;
  }

  /** Generates a fresh X25519 keypair. */
  public static MailboxPrivateKey generate(int keyVersion) throws CryptoException {
    byte[] raw = X25519.generatePrivateKey();
    return fromBytes(keyVersion, Secret.wrap(raw));
  }

  /** Reconstructs a private key; takes ownership of {@code privateBytes}. */
  @AccessesPartialKey
  static MailboxPrivateKey fromBytes(int keyVersion, Secret privateBytes) throws CryptoException {
    try {
      byte[] publicBytes = X25519.publicFromPrivate(privateBytes.bytes());
      MailboxPublicKey publicKey = new MailboxPublicKey(keyVersion, publicBytes);
      HpkePublicKey hpkePublic =
          HpkePublicKey.create(CryptoProfile.hpke(), Bytes.copyFrom(publicBytes), null);
      HpkePrivateKey hpkePrivate =
          HpkePrivateKey.create(
              hpkePublic,
              SecretBytes.copyFrom(privateBytes.bytes(), InsecureSecretKeyAccess.get()));
      KeysetHandle handle =
          KeysetHandle.newBuilder()
              .addEntry(KeysetHandle.importKey(hpkePrivate).withRandomId().makePrimary())
              .build();
      HybridDecrypt decrypt = handle.getPrimitive(HybridConfig2026.get(), HybridDecrypt.class);
      return new MailboxPrivateKey(publicKey, privateBytes, decrypt);
    } catch (GeneralSecurityException | IllegalArgumentException e) {
      privateBytes.close();
      throw new CryptoException("invalid private key", e);
    }
  }

  public MailboxPublicKey publicKey() {
    return publicKey;
  }

  public int keyVersion() {
    return publicKey.keyVersion();
  }

  HybridDecrypt decrypt() {
    if (privateBytes.isClosed()) {
      throw new IllegalStateException("private key closed");
    }
    return decrypt;
  }

  Secret privateBytes() {
    return privateBytes;
  }

  @Override
  public void close() {
    privateBytes.close();
  }

  @Override
  public String toString() {
    return "MailboxPrivateKey[v" + keyVersion() + ", redacted]";
  }
}
