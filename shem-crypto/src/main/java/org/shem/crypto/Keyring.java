package org.shem.crypto;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.NavigableMap;
import java.util.Objects;
import java.util.Optional;
import java.util.TreeMap;
import org.shem.common.FormatException;
import org.shem.common.OpaqueId;
import org.shem.common.RecordReader;
import org.shem.common.RecordWriter;

/**
 * Decrypted mailbox key hierarchy, held only under an unlock lease.
 *
 * <p>Contents: mailbox private keys by version (the current one plus versions retained until all
 * receipts sealed to them are imported), data root keys by version (metadata, content-key wraps,
 * search index), and slot descriptors. The whole record is encrypted under the mailbox master key,
 * which only credential slots can unwrap. A monotonic generation is authenticated with the record;
 * rollback of the whole file to an older valid generation needs external freshness state to detect
 * (documented limitation).
 */
public final class Keyring implements AutoCloseable {
  private static final byte[] MAGIC = {'S', 'H', 'K', 'R'};

  /** Format 2 adds MFA factors; format 1 keyrings remain readable (and have none). */
  private static final int FORMAT = 2;

  private static final int MAX_FACTORS = 16;
  private static final int MAX_KEYS = 64;
  private static final int MAX_SLOTS = 256;

  private final OpaqueId mailboxId;
  private final long generation;
  private final int currentKeyVersion;
  private final int currentDataVersion;
  private final NavigableMap<Integer, MailboxPrivateKey> privateKeys;
  private final NavigableMap<Integer, SymmetricKey> dataRoots;
  private final List<SlotDescriptor> slots;
  private final List<MfaFactor> factors;

  private Keyring(
      OpaqueId mailboxId,
      long generation,
      int currentKeyVersion,
      int currentDataVersion,
      NavigableMap<Integer, MailboxPrivateKey> privateKeys,
      NavigableMap<Integer, SymmetricKey> dataRoots,
      List<SlotDescriptor> slots,
      List<MfaFactor> factors) {
    if (!privateKeys.containsKey(currentKeyVersion) || !dataRoots.containsKey(currentDataVersion)) {
      throw new IllegalArgumentException("current key missing from keyring");
    }
    if (factors.size() > MAX_FACTORS) {
      throw new IllegalArgumentException("too many factors");
    }
    this.mailboxId = mailboxId;
    this.generation = generation;
    this.currentKeyVersion = currentKeyVersion;
    this.currentDataVersion = currentDataVersion;
    this.privateKeys = privateKeys;
    this.dataRoots = dataRoots;
    this.slots = List.copyOf(slots);
    this.factors = List.copyOf(factors);
  }

  /** A new keyring with one keypair and one data root, taking ownership of both. */
  public static Keyring create(
      OpaqueId mailboxId, MailboxPrivateKey privateKey, SymmetricKey dataRoot, int dataVersion) {
    NavigableMap<Integer, MailboxPrivateKey> keys = new TreeMap<>();
    keys.put(privateKey.keyVersion(), privateKey);
    NavigableMap<Integer, SymmetricKey> roots = new TreeMap<>();
    roots.put(dataVersion, dataRoot);
    return new Keyring(
        mailboxId, 1, privateKey.keyVersion(), dataVersion, keys, roots, List.of(), List.of());
  }

  public OpaqueId mailboxId() {
    return mailboxId;
  }

  public long generation() {
    return generation;
  }

  public MailboxPrivateKey currentPrivateKey() {
    return Objects.requireNonNull(privateKeys.get(currentKeyVersion));
  }

  public MailboxPublicKey currentPublicKey() {
    return currentPrivateKey().publicKey();
  }

  public Optional<MailboxPrivateKey> privateKey(int keyVersion) {
    return Optional.ofNullable(privateKeys.get(keyVersion));
  }

  public Map<Integer, MailboxPrivateKey> privateKeys() {
    return Collections.unmodifiableMap(privateKeys);
  }

  public int currentDataVersion() {
    return currentDataVersion;
  }

  public SymmetricKey currentDataRoot() {
    return Objects.requireNonNull(dataRoots.get(currentDataVersion));
  }

  public Optional<SymmetricKey> dataRoot(int version) {
    return Optional.ofNullable(dataRoots.get(version));
  }

  public List<Integer> dataVersions() {
    return List.copyOf(dataRoots.keySet());
  }

  public List<SlotDescriptor> slots() {
    return slots;
  }

  public Optional<SlotDescriptor> slot(OpaqueId slotId) {
    return slots.stream().filter(s -> s.slotId().equals(slotId)).findFirst();
  }

  /** The second factors (owned by this keyring; do not close). */
  public List<MfaFactor> factors() {
    return factors;
  }

  /** Copy with the next generation and a different factor list, taking ownership of its entries. */
  public Keyring withFactors(List<MfaFactor> newFactors) {
    if (newFactors.size() > MAX_FACTORS) {
      newFactors.forEach(MfaFactor::close);
      throw new IllegalArgumentException("too many factors");
    }
    return new Keyring(
        mailboxId,
        generation + 1,
        currentKeyVersion,
        currentDataVersion,
        copyKeys(),
        copyRoots(),
        slots,
        newFactors);
  }

  /** Copy with the next generation and a different slot list. */
  public Keyring withSlots(List<SlotDescriptor> newSlots) {
    if (newSlots.size() > MAX_SLOTS) {
      throw new IllegalArgumentException("too many slots");
    }
    return new Keyring(
        mailboxId,
        generation + 1,
        currentKeyVersion,
        currentDataVersion,
        copyKeys(),
        copyRoots(),
        newSlots,
        copyFactors());
  }

  public Keyring withSlotAdded(SlotDescriptor slot) {
    List<SlotDescriptor> next = new ArrayList<>(slots);
    next.add(slot);
    return withSlots(next);
  }

  public Keyring withSlotRemoved(OpaqueId slotId) {
    List<SlotDescriptor> next = new ArrayList<>(slots);
    next.removeIf(s -> s.slotId().equals(slotId));
    return withSlots(next);
  }

  /**
   * Adds a new current keypair and data root while retaining the old ones for pending receipts and
   * metadata re-encryption. Takes ownership of the new keys.
   */
  public Keyring withRotatedKeys(
      MailboxPrivateKey newPrivateKey, SymmetricKey newDataRoot, int newDataVersion) {
    if (newPrivateKey.keyVersion() <= privateKeys.lastKey()
        || newDataVersion <= dataRoots.lastKey()) {
      throw new IllegalArgumentException("rotated key versions must increase");
    }
    NavigableMap<Integer, MailboxPrivateKey> keys = copyKeys();
    keys.put(newPrivateKey.keyVersion(), newPrivateKey);
    NavigableMap<Integer, SymmetricKey> roots = copyRoots();
    roots.put(newDataVersion, newDataRoot);
    if (keys.size() > MAX_KEYS || roots.size() > MAX_KEYS) {
      throw new IllegalArgumentException("too many retained keys");
    }
    return new Keyring(
        mailboxId,
        generation + 1,
        newPrivateKey.keyVersion(),
        newDataVersion,
        keys,
        roots,
        slots,
        copyFactors());
  }

  /** Drops retained non-current versions once nothing references them. */
  public Keyring withRetiredVersions(List<Integer> keyVersions, List<Integer> dataVersions) {
    NavigableMap<Integer, MailboxPrivateKey> keys = copyKeys();
    for (int version : keyVersions) {
      if (version != currentKeyVersion) {
        MailboxPrivateKey removed = keys.remove(version);
        if (removed != null) {
          removed.close();
        }
      }
    }
    NavigableMap<Integer, SymmetricKey> roots = copyRoots();
    for (int version : dataVersions) {
      if (version != currentDataVersion) {
        SymmetricKey removed = roots.remove(version);
        if (removed != null) {
          removed.close();
        }
      }
    }
    return new Keyring(
        mailboxId,
        generation + 1,
        currentKeyVersion,
        currentDataVersion,
        keys,
        roots,
        slots,
        copyFactors());
  }

  public byte[] seal(SymmetricKey masterKey) throws CryptoException {
    RecordWriter body = new RecordWriter().u32(currentKeyVersion).u32(currentDataVersion);
    body.u16(privateKeys.size());
    for (MailboxPrivateKey key : privateKeys.values()) {
      body.u32(key.keyVersion()).bytes(key.privateBytes().bytes());
    }
    body.u16(dataRoots.size());
    for (Map.Entry<Integer, SymmetricKey> root : dataRoots.entrySet()) {
      body.u32(root.getKey()).bytes(root.getValue().secret().bytes());
    }
    body.u16(slots.size());
    for (SlotDescriptor slot : slots) {
      body.id(slot.slotId())
          .u8(slot.kind().code())
          .string(slot.label())
          .i64(slot.createdAt().getEpochSecond());
    }
    body.u16(factors.size());
    for (MfaFactor factor : factors) {
      body.id(factor.id())
          .u8(factor.kind().code())
          .string(factor.label())
          .i64(factor.createdAt().getEpochSecond())
          .i64(factor.counter())
          .bytes(factor.material().bytes());
    }
    byte[] plaintext = body.toByteArrayAndWipe();
    try {
      byte[] ciphertext = masterKey.seal(plaintext, context(mailboxId, generation, FORMAT));
      return new RecordWriter()
          .raw(MAGIC)
          .u8(FORMAT)
          .u8(CryptoProfile.PROFILE_VERSION)
          .id(mailboxId)
          .i64(generation)
          .bytes(ciphertext)
          .toByteArray();
    } finally {
      java.util.Arrays.fill(plaintext, (byte) 0);
    }
  }

  /** Reads only the public header (mailbox and generation) of a sealed keyring. */
  public static long generationOf(byte[] sealed) throws FormatException {
    RecordReader reader = header(sealed);
    reader.id();
    return reader.i64();
  }

  public static Keyring open(byte[] sealed, OpaqueId expectedMailbox, SymmetricKey masterKey)
      throws CryptoException, FormatException {
    int format = formatOf(sealed);
    RecordReader outer = header(sealed);
    OpaqueId mailboxId = outer.id();
    long generation = outer.i64();
    byte[] ciphertext = outer.bytes(1 << 20);
    outer.expectEnd();
    if (!mailboxId.equals(expectedMailbox)) {
      throw new FormatException("keyring belongs to another mailbox");
    }
    NavigableMap<Integer, MailboxPrivateKey> keys = new TreeMap<>();
    NavigableMap<Integer, SymmetricKey> roots = new TreeMap<>();
    List<MfaFactor> factors = new ArrayList<>();
    try (Secret plaintext = masterKey.open(ciphertext, context(mailboxId, generation, format))) {
      RecordReader reader = new RecordReader(plaintext.bytes());
      int currentKeyVersion = (int) reader.u32();
      int currentDataVersion = (int) reader.u32();
      int keyCount = reader.u16();
      if (keyCount > MAX_KEYS) {
        throw new FormatException("too many keys");
      }
      for (int i = 0; i < keyCount; i++) {
        int version = (int) reader.u32();
        keys.put(version, MailboxPrivateKey.fromBytes(version, Secret.wrap(reader.bytes(64))));
      }
      int rootCount = reader.u16();
      if (rootCount > MAX_KEYS) {
        throw new FormatException("too many data roots");
      }
      for (int i = 0; i < rootCount; i++) {
        int version = (int) reader.u32();
        roots.put(version, SymmetricKey.of(Secret.wrap(reader.bytes(64))));
      }
      int slotCount = reader.u16();
      if (slotCount > MAX_SLOTS) {
        throw new FormatException("too many slots");
      }
      List<SlotDescriptor> slots = new ArrayList<>();
      for (int i = 0; i < slotCount; i++) {
        OpaqueId slotId = reader.id();
        SlotKind kind = SlotKind.fromCode(reader.u8());
        String label = reader.string(SlotDescriptor.MAX_LABEL_BYTES);
        slots.add(new SlotDescriptor(slotId, kind, label, Instant.ofEpochSecond(reader.i64())));
      }
      if (format >= 2) {
        int factorCount = reader.u16();
        if (factorCount > MAX_FACTORS) {
          throw new FormatException("too many factors");
        }
        for (int i = 0; i < factorCount; i++) {
          OpaqueId factorId = reader.id();
          MfaFactor.Kind kind = MfaFactor.Kind.fromCode(reader.u8());
          String label = reader.string(MfaFactor.MAX_LABEL_BYTES);
          Instant created = Instant.ofEpochSecond(reader.i64());
          long counter = reader.i64();
          factors.add(
              new MfaFactor(
                  factorId,
                  kind,
                  label,
                  created,
                  counter,
                  Secret.wrap(reader.bytes(MfaFactor.MAX_MATERIAL_BYTES))));
        }
      }
      reader.expectEnd();
      return new Keyring(
          mailboxId,
          generation,
          currentKeyVersion,
          currentDataVersion,
          keys,
          roots,
          slots,
          factors);
    } catch (FormatException | CryptoException | IllegalArgumentException e) {
      keys.values().forEach(MailboxPrivateKey::close);
      roots.values().forEach(SymmetricKey::close);
      factors.forEach(MfaFactor::close);
      if (e instanceof IllegalArgumentException) {
        throw new FormatException("invalid keyring contents", e);
      }
      throw e;
    }
  }

  private static RecordReader header(byte[] sealed) throws FormatException {
    RecordReader reader = new RecordReader(sealed);
    if (!java.util.Arrays.equals(reader.raw(4), MAGIC)) {
      throw new FormatException("not a keyring");
    }
    int format = reader.u8();
    if ((format != 1 && format != FORMAT) || reader.u8() != CryptoProfile.PROFILE_VERSION) {
      throw new FormatException("unsupported keyring version");
    }
    return reader;
  }

  private static int formatOf(byte[] sealed) throws FormatException {
    RecordReader reader = new RecordReader(sealed);
    reader.raw(4);
    return reader.u8();
  }

  /** The format version is bound into the associated data, so a downgrade fails to open. */
  private static AssociatedData context(OpaqueId mailboxId, long generation, int format) {
    return AssociatedData.builder(Purpose.KEYRING, format)
        .id("mailbox", mailboxId)
        .number("generation", generation)
        .build();
  }

  private NavigableMap<Integer, MailboxPrivateKey> copyKeys() {
    NavigableMap<Integer, MailboxPrivateKey> copy = new TreeMap<>();
    for (Map.Entry<Integer, MailboxPrivateKey> entry : privateKeys.entrySet()) {
      try {
        copy.put(
            entry.getKey(),
            MailboxPrivateKey.fromBytes(entry.getKey(), entry.getValue().privateBytes().copy()));
      } catch (CryptoException e) {
        throw new IllegalStateException("in-memory key copy failed", e);
      }
    }
    return copy;
  }

  private List<MfaFactor> copyFactors() {
    List<MfaFactor> copy = new ArrayList<>();
    factors.forEach(f -> copy.add(f.copy()));
    return copy;
  }

  private NavigableMap<Integer, SymmetricKey> copyRoots() {
    NavigableMap<Integer, SymmetricKey> copy = new TreeMap<>();
    dataRoots.forEach((version, key) -> copy.put(version, key.copy()));
    return copy;
  }

  /** Wipes all key material held by this keyring object. */
  @Override
  public void close() {
    privateKeys.values().forEach(MailboxPrivateKey::close);
    dataRoots.values().forEach(SymmetricKey::close);
    factors.forEach(MfaFactor::close);
  }

  @Override
  public String toString() {
    return "Keyring[generation=" + generation + ", redacted]";
  }
}
