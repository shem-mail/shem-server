package org.shem.common;

import java.security.SecureRandom;

/** Source of fresh opaque identifiers; a seam for deterministic tests. */
@FunctionalInterface
public interface IdGenerator {
  OpaqueId next();

  /** Production generator backed by a cryptographically secure RNG. */
  static IdGenerator secure(SecureRandom random) {
    return () -> OpaqueId.random(random);
  }
}
