package org.shem.crypto;

import java.util.Arrays;
import org.shem.common.OpaqueId;
import org.shem.common.RecordWriter;

/**
 * Canonical associated data binding ciphertext to its context: profile, purpose, format version,
 * mailbox, object, and any positional fields. Field names are encoded alongside values so two
 * different field sequences can never collide.
 */
public final class AssociatedData {
  private static final String DOMAIN = "shem/aad/v1";
  private final byte[] encoded;

  private AssociatedData(byte[] encoded) {
    this.encoded = encoded;
  }

  public static Builder builder(Purpose purpose, int formatVersion) {
    return new Builder(purpose, formatVersion);
  }

  /** Returns a copy of the encoded bytes. */
  public byte[] toBytes() {
    return encoded.clone();
  }

  byte[] bytes() {
    return encoded;
  }

  @Override
  public boolean equals(Object obj) {
    return obj instanceof AssociatedData other && Arrays.equals(encoded, other.encoded);
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(encoded);
  }

  @Override
  public String toString() {
    return "AssociatedData[" + encoded.length + " bytes]";
  }

  /** Builder; field names must be fixed constants, never user data. */
  public static final class Builder {
    private final RecordWriter writer = new RecordWriter();

    private Builder(Purpose purpose, int formatVersion) {
      writer.string(DOMAIN).string(purpose.label()).u16(formatVersion);
    }

    public Builder id(String field, OpaqueId value) {
      writer.string(field).u8(1).id(value);
      return this;
    }

    public Builder number(String field, long value) {
      writer.string(field).u8(2).i64(value);
      return this;
    }

    public Builder text(String field, String value) {
      writer.string(field).u8(3).string(value);
      return this;
    }

    public Builder bytes(String field, byte[] value) {
      writer.string(field).u8(4).bytes(value);
      return this;
    }

    public AssociatedData build() {
      return new AssociatedData(writer.toByteArray());
    }
  }
}
