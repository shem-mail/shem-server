package org.shem.crypto;

import com.google.crypto.tink.aead.AesGcmParameters;
import com.google.crypto.tink.hybrid.HpkeParameters;
import com.google.crypto.tink.streamingaead.AesGcmHkdfStreamingParameters;
import java.security.GeneralSecurityException;

/**
 * Profile 1, the only supported profile. Algorithms come from Google Tink; this class pins their
 * parameters. Changing anything here requires a new profile number and a migration plan.
 *
 * <ul>
 *   <li>Public-key envelopes: HPKE (RFC 9180) base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
 *       AES-256-GCM.
 *   <li>Content and file encryption: Tink AES-256-GCM-HKDF streaming AEAD (segmented, per-stream
 *       random salt and nonce prefix, final-segment flag, seekable decryption).
 *   <li>Small records: AES-256-GCM with 96-bit random nonces under per-purpose derived keys.
 *   <li>Key derivation: HKDF-SHA256 with purpose labels; credentials: Argon2id (Bouncy Castle).
 * </ul>
 */
public final class CryptoProfile {
  public static final int PROFILE_VERSION = 1;
  public static final int SYMMETRIC_KEY_BYTES = 32;
  public static final int BLOB_SEGMENT_BYTES = 64 * 1024;
  public static final int FILE_SEGMENT_BYTES = 16 * 1024;

  private CryptoProfile() {}

  static HpkeParameters hpke() throws GeneralSecurityException {
    return HpkeParameters.builder()
        .setKemId(HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)
        .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
        .setAeadId(HpkeParameters.AeadId.AES_256_GCM)
        .setVariant(HpkeParameters.Variant.NO_PREFIX)
        .build();
  }

  static AesGcmHkdfStreamingParameters streaming(int segmentBytes) throws GeneralSecurityException {
    return AesGcmHkdfStreamingParameters.builder()
        .setKeySizeBytes(SYMMETRIC_KEY_BYTES)
        .setDerivedAesGcmKeySizeBytes(SYMMETRIC_KEY_BYTES)
        .setHkdfHashType(AesGcmHkdfStreamingParameters.HashType.SHA256)
        .setCiphertextSegmentSizeBytes(segmentBytes)
        .build();
  }

  static AesGcmParameters aesGcm() throws GeneralSecurityException {
    return AesGcmParameters.builder()
        .setKeySizeBytes(SYMMETRIC_KEY_BYTES)
        .setIvSizeBytes(12)
        .setTagSizeBytes(16)
        .setVariant(AesGcmParameters.Variant.NO_PREFIX)
        .build();
  }
}
