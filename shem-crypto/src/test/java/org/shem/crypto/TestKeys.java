package org.shem.crypto;

import java.security.SecureRandom;
import java.time.Duration;
import org.shem.common.OpaqueId;

/** Cheap KDF settings for unit tests only. Production limits reject these parameters. */
final class TestKeys {
  static final SecureRandom RANDOM = new SecureRandom();
  static final Argon2Parameters.Limits TEST_LIMITS = new Argon2Parameters.Limits(8, 1 << 20, 10, 8);
  static final Argon2Parameters CHEAP = new Argon2Parameters(64, 1, 1);

  private TestKeys() {}

  static Argon2idKdf kdf() {
    return new Argon2idKdf(new KdfAdmission(1 << 20, Duration.ofSeconds(5)), TEST_LIMITS);
  }

  static OpaqueId id() {
    return OpaqueId.random(RANDOM);
  }
}
