package org.shem.crypto;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import org.shem.common.OpaqueId;

/**
 * A second-factor credential kept inside the sealed keyring, so it is encrypted under the master
 * key and rewritten atomically with every key change (ADR 0014). {@code material} is the TOTP
 * secret, or the serialized WebAuthn credential (public key and credential id); {@code counter} is
 * the last accepted TOTP time step or WebAuthn signature counter, for replay protection. Owns its
 * material; {@link #close()} wipes it.
 */
public final class MfaFactor implements AutoCloseable {
  public static final int MAX_MATERIAL_BYTES = 4096;
  public static final int MAX_LABEL_BYTES = 64;

  /** Factor type; codes are persisted and never reused. */
  public enum Kind {
    TOTP(1),
    WEBAUTHN(2);

    private final int code;

    Kind(int code) {
      this.code = code;
    }

    public int code() {
      return code;
    }

    static Kind fromCode(int code) {
      for (Kind kind : values()) {
        if (kind.code == code) {
          return kind;
        }
      }
      throw new IllegalArgumentException("unknown factor kind");
    }
  }

  private final OpaqueId id;
  private final Kind kind;
  private final String label;
  private final Instant createdAt;
  private final long counter;
  private final Secret material;

  /** Takes ownership of {@code material}. */
  public MfaFactor(
      OpaqueId id, Kind kind, String label, Instant createdAt, long counter, Secret material) {
    if (label.getBytes(StandardCharsets.UTF_8).length > MAX_LABEL_BYTES
        || material.length() > MAX_MATERIAL_BYTES
        || counter < 0) {
      material.close();
      throw new IllegalArgumentException("invalid factor");
    }
    this.id = id;
    this.kind = kind;
    this.label = label;
    this.createdAt = createdAt;
    this.counter = counter;
    this.material = material;
  }

  public OpaqueId id() {
    return id;
  }

  public Kind kind() {
    return kind;
  }

  public String label() {
    return label;
  }

  public Instant createdAt() {
    return createdAt;
  }

  public long counter() {
    return counter;
  }

  /** The secret material, still owned by this factor. */
  public Secret material() {
    return material;
  }

  public MfaFactor copy() {
    return new MfaFactor(id, kind, label, createdAt, counter, material.copy());
  }

  public MfaFactor withCounter(long next) {
    return new MfaFactor(id, kind, label, createdAt, next, material.copy());
  }

  @Override
  public void close() {
    material.close();
  }

  @Override
  public String toString() {
    return "MfaFactor[" + kind + ", redacted]";
  }
}
