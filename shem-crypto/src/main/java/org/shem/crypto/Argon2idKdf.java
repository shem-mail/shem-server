package org.shem.crypto;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;

/** Argon2id (RFC 9106, version 0x13) from Bouncy Castle, gated by {@link KdfAdmission}. */
public final class Argon2idKdf {
  private final KdfAdmission admission;
  private final Argon2Parameters.Limits limits;

  public Argon2idKdf(KdfAdmission admission, Argon2Parameters.Limits limits) {
    this.admission = admission;
    this.limits = limits;
  }

  public Argon2Parameters.Limits limits() {
    return limits;
  }

  /**
   * Derives a 32-byte key-encryption key. The credential is not consumed. Bouncy Castle copies the
   * password internally while hashing; those copies are outside Shem's control.
   */
  public Secret derive(Secret credential, byte[] salt, Argon2Parameters parameters)
      throws CryptoException, KdfAdmission.Rejected, InterruptedException {
    if (!limits.accepts(parameters)) {
      throw new CryptoException("Argon2id parameters outside accepted bounds");
    }
    if (salt.length < 16 || salt.length > 64) {
      throw new CryptoException("invalid salt length");
    }
    KdfAdmission.Permit permit = admission.acquire(parameters);
    try {
      org.bouncycastle.crypto.params.Argon2Parameters bcParameters =
          new org.bouncycastle.crypto.params.Argon2Parameters.Builder(
                  org.bouncycastle.crypto.params.Argon2Parameters.ARGON2_id)
              .withVersion(org.bouncycastle.crypto.params.Argon2Parameters.ARGON2_VERSION_13)
              .withMemoryAsKB(parameters.memoryKiB())
              .withIterations(parameters.iterations())
              .withParallelism(parameters.parallelism())
              .withSalt(salt)
              .build();
      Argon2BytesGenerator generator = new Argon2BytesGenerator();
      generator.init(bcParameters);
      byte[] out = new byte[CryptoProfile.SYMMETRIC_KEY_BYTES];
      generator.generateBytes(credential.bytes(), out);
      return Secret.wrap(out);
    } finally {
      permit.close();
    }
  }
}
