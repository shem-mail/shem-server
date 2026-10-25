package org.shem.crypto;

import java.security.SecureRandom;
import org.shem.common.FormatException;
import org.shem.common.OpaqueId;
import org.shem.common.RecordReader;
import org.shem.common.RecordWriter;

/**
 * A credential slot: the mailbox master key wrapped under an Argon2id-derived key-encryption key.
 *
 * <p>A successful unwrap is the credential check; there is no separate password hash. Persisted
 * form: {@code "SHSL", u8 format, u8 profile, id mailbox, id slot, u8 kind, u32 memKiB, u32 iter,
 * u32 par, bytes salt, bytes wrappedMasterKey}. Everything except the wrapped key is authenticated
 * as associated data, so parameters, kind, and identities cannot be swapped.
 */
public final class KeySlot {
  private static final byte[] MAGIC = {'S', 'H', 'S', 'L'};
  private static final int FORMAT = 1;
  private static final int SALT_BYTES = 16;

  private final OpaqueId mailboxId;
  private final OpaqueId slotId;
  private final SlotKind kind;
  private final Argon2Parameters parameters;
  private final byte[] salt;
  private final byte[] wrapped;

  private KeySlot(
      OpaqueId mailboxId,
      OpaqueId slotId,
      SlotKind kind,
      Argon2Parameters parameters,
      byte[] salt,
      byte[] wrapped) {
    this.mailboxId = mailboxId;
    this.slotId = slotId;
    this.kind = kind;
    this.parameters = parameters;
    this.salt = salt;
    this.wrapped = wrapped;
  }

  /** Creates a slot protecting {@code masterKey} under {@code credential}. */
  public static KeySlot create(
      OpaqueId mailboxId,
      OpaqueId slotId,
      SlotKind kind,
      Secret credential,
      SymmetricKey masterKey,
      Argon2Parameters parameters,
      Argon2idKdf kdf,
      SecureRandom random)
      throws CryptoException, KdfAdmission.Rejected, InterruptedException {
    byte[] salt = new byte[SALT_BYTES];
    random.nextBytes(salt);
    AssociatedData context = context(mailboxId, slotId, kind, parameters, salt);
    try (Secret kek = kdf.derive(credential, salt, parameters);
        SymmetricKey wrappingKey = SymmetricKey.of(kek.copy())) {
      byte[] wrapped = wrappingKey.wrap(masterKey.secret(), context);
      return new KeySlot(mailboxId, slotId, kind, parameters, salt, wrapped);
    }
  }

  /** Unwraps the master key; a {@link CryptoException} means the credential is wrong. */
  public SymmetricKey unwrap(Secret credential, Argon2idKdf kdf)
      throws CryptoException, KdfAdmission.Rejected, InterruptedException {
    AssociatedData context = context(mailboxId, slotId, kind, parameters, salt);
    try (Secret kek = kdf.derive(credential, salt, parameters);
        SymmetricKey wrappingKey = SymmetricKey.of(kek.copy())) {
      return SymmetricKey.of(wrappingKey.open(wrapped, context));
    }
  }

  public OpaqueId mailboxId() {
    return mailboxId;
  }

  public OpaqueId slotId() {
    return slotId;
  }

  public SlotKind kind() {
    return kind;
  }

  public Argon2Parameters parameters() {
    return parameters;
  }

  public byte[] encode() {
    return new RecordWriter()
        .raw(MAGIC)
        .u8(FORMAT)
        .u8(CryptoProfile.PROFILE_VERSION)
        .id(mailboxId)
        .id(slotId)
        .u8(kind.code())
        .u32(parameters.memoryKiB())
        .u32(parameters.iterations())
        .u32(parameters.parallelism())
        .bytes(salt)
        .bytes(wrapped)
        .toByteArray();
  }

  /** Decodes and validates a stored slot; KDF limits are enforced before any derivation. */
  public static KeySlot decode(byte[] encoded, Argon2Parameters.Limits limits)
      throws FormatException {
    RecordReader reader = new RecordReader(encoded);
    if (!java.util.Arrays.equals(reader.raw(4), MAGIC)) {
      throw new FormatException("not a key slot");
    }
    if (reader.u8() != FORMAT || reader.u8() != CryptoProfile.PROFILE_VERSION) {
      throw new FormatException("unsupported key slot version");
    }
    OpaqueId mailboxId = reader.id();
    OpaqueId slotId = reader.id();
    SlotKind kind;
    Argon2Parameters parameters;
    try {
      kind = SlotKind.fromCode(reader.u8());
      parameters =
          new Argon2Parameters(
              checkedInt(reader.u32()), checkedInt(reader.u32()), checkedInt(reader.u32()));
    } catch (IllegalArgumentException e) {
      throw new FormatException("invalid key slot fields", e);
    }
    if (!limits.accepts(parameters)) {
      throw new FormatException("key slot KDF parameters outside accepted bounds");
    }
    byte[] salt = reader.bytes(64);
    if (salt.length != SALT_BYTES) {
      throw new FormatException("invalid salt");
    }
    byte[] wrapped = reader.bytes(256);
    reader.expectEnd();
    return new KeySlot(mailboxId, slotId, kind, parameters, salt, wrapped);
  }

  private static int checkedInt(long value) throws FormatException {
    if (value > Integer.MAX_VALUE) {
      throw new FormatException("value out of range");
    }
    return (int) value;
  }

  private static AssociatedData context(
      OpaqueId mailboxId,
      OpaqueId slotId,
      SlotKind kind,
      Argon2Parameters parameters,
      byte[] salt) {
    return AssociatedData.builder(Purpose.CREDENTIAL_SLOT, FORMAT)
        .id("mailbox", mailboxId)
        .id("slot", slotId)
        .number("kind", kind.code())
        .number("memory", parameters.memoryKiB())
        .number("iterations", parameters.iterations())
        .number("parallelism", parameters.parallelism())
        .bytes("salt", salt)
        .build();
  }
}
