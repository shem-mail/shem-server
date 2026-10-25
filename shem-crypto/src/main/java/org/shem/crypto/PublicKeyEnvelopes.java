package org.shem.crypto;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.hybrid.HpkePublicKey;
import com.google.crypto.tink.hybrid.HybridConfig2026;
import com.google.crypto.tink.util.Bytes;
import java.security.GeneralSecurityException;
import org.shem.common.FormatException;
import org.shem.common.RecordReader;
import org.shem.common.RecordWriter;

/**
 * Seals small secrets (content keys, receipt keys) to a mailbox public key with HPKE.
 *
 * <p>Wire format: {@code u8 format=1, u8 profile, u32 keyVersion, bytes hpkeCiphertext}. The key
 * version is authenticated by also binding it into the HPKE context info, so an envelope cannot be
 * relabelled to another key version.
 */
public final class PublicKeyEnvelopes {
  private static final int FORMAT = 1;
  private static final int MAX_CIPHERTEXT = 4096;

  private PublicKeyEnvelopes() {}

  @AccessesPartialKey
  public static byte[] seal(MailboxPublicKey recipient, AssociatedData context, Secret payload)
      throws CryptoException {
    try {
      HpkePublicKey key =
          HpkePublicKey.create(CryptoProfile.hpke(), Bytes.copyFrom(recipient.bytes()), null);
      HybridEncrypt encrypt =
          KeysetHandle.newBuilder()
              .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
              .build()
              .getPrimitive(HybridConfig2026.get(), HybridEncrypt.class);
      byte[] ciphertext =
          encrypt.encrypt(payload.bytes(), contextInfo(recipient.keyVersion(), context));
      return new RecordWriter()
          .u8(FORMAT)
          .u8(CryptoProfile.PROFILE_VERSION)
          .u32(recipient.keyVersion())
          .bytes(ciphertext)
          .toByteArray();
    } catch (GeneralSecurityException e) {
      throw new CryptoException("envelope sealing failed", e);
    }
  }

  /** Seals a symmetric key (for example a per-message content key). */
  public static byte[] sealKey(MailboxPublicKey recipient, AssociatedData context, SymmetricKey key)
      throws CryptoException {
    return seal(recipient, context, key.secret());
  }

  public static SymmetricKey openKey(MailboxPrivateKey key, AssociatedData context, byte[] envelope)
      throws CryptoException {
    Secret secret = open(key, context, envelope);
    try {
      return SymmetricKey.of(secret);
    } catch (IllegalArgumentException e) {
      throw new CryptoException("envelope does not contain a symmetric key", e);
    }
  }

  /** Reads the key version an envelope was sealed to, without decrypting. */
  public static int keyVersionOf(byte[] envelope) throws CryptoException {
    try {
      RecordReader reader = header(envelope);
      return (int) reader.u32();
    } catch (FormatException e) {
      throw new CryptoException("malformed envelope", e);
    }
  }

  public static Secret open(MailboxPrivateKey key, AssociatedData context, byte[] envelope)
      throws CryptoException {
    try {
      RecordReader reader = header(envelope);
      long keyVersion = reader.u32();
      byte[] ciphertext = reader.bytes(MAX_CIPHERTEXT);
      reader.expectEnd();
      if (keyVersion != key.keyVersion()) {
        throw new CryptoException("envelope sealed to a different key version");
      }
      return Secret.wrap(key.decrypt().decrypt(ciphertext, contextInfo(key.keyVersion(), context)));
    } catch (FormatException e) {
      throw new CryptoException("malformed envelope", e);
    } catch (GeneralSecurityException e) {
      throw new CryptoException("envelope authentication failed", e);
    }
  }

  private static RecordReader header(byte[] envelope) throws FormatException {
    RecordReader reader = new RecordReader(envelope);
    if (reader.u8() != FORMAT) {
      throw new FormatException("unknown envelope format");
    }
    if (reader.u8() != CryptoProfile.PROFILE_VERSION) {
      throw new FormatException("unknown crypto profile");
    }
    return reader;
  }

  private static byte[] contextInfo(int keyVersion, AssociatedData context) {
    return new RecordWriter()
        .string("shem/hpke/v1")
        .u32(keyVersion)
        .bytes(context.bytes())
        .toByteArray();
  }
}
