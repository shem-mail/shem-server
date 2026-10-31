package org.shem.store.metadata;

import java.util.ArrayList;
import java.util.List;
import org.jspecify.annotations.Nullable;
import org.shem.common.FormatException;
import org.shem.common.OpaqueId;
import org.shem.common.RecordReader;
import org.shem.common.RecordWriter;
import org.shem.crypto.AssociatedData;
import org.shem.crypto.CryptoException;
import org.shem.crypto.CryptoProfile;
import org.shem.crypto.Purpose;
import org.shem.crypto.Secret;
import org.shem.crypto.SymmetricKey;

/**
 * Authenticated commit manifest linking the current snapshot and journal segments. Plaintext header
 * {@code "SHMM", u8 format, u8 profile, id mailbox, u32 dataVersion, i64 generation} (the data
 * version selects the key); body encrypted under a manifest key derived from the data root.
 */
record Manifest(
    long generation,
    int dataVersion,
    @Nullable OpaqueId snapshotId,
    List<OpaqueId> sealedSegments,
    OpaqueId activeSegment) {
  static final String FILE = "manifest";
  private static final byte[] MAGIC = {'S', 'H', 'M', 'M'};
  private static final int FORMAT = 1;

  Manifest {
    sealedSegments = List.copyOf(sealedSegments);
  }

  byte[] seal(OpaqueId mailboxId, SymmetricKey dataRoot) throws CryptoException {
    RecordWriter body = new RecordWriter().bool(snapshotId != null);
    if (snapshotId != null) {
      body.id(snapshotId);
    }
    body.u32(sealedSegments.size());
    sealedSegments.forEach(body::id);
    body.id(activeSegment);
    try (SymmetricKey key = dataRoot.derive(Purpose.METADATA_MANIFEST, mailboxId.toBytes())) {
      byte[] ciphertext = key.seal(body.toByteArray(), context(mailboxId, dataVersion, generation));
      return new RecordWriter()
          .raw(MAGIC)
          .u8(FORMAT)
          .u8(CryptoProfile.PROFILE_VERSION)
          .id(mailboxId)
          .u32(dataVersion)
          .i64(generation)
          .bytes(ciphertext)
          .toByteArray();
    }
  }

  /** Reads the data version from the plaintext header so the caller can select the key. */
  static int dataVersionOf(byte[] sealed, OpaqueId mailboxId) throws FormatException {
    RecordReader in = header(sealed, mailboxId);
    return (int) in.u32();
  }

  static Manifest open(byte[] sealed, OpaqueId mailboxId, SymmetricKey dataRoot)
      throws FormatException, CryptoException {
    RecordReader in = header(sealed, mailboxId);
    int dataVersion = (int) in.u32();
    long generation = in.i64();
    byte[] ciphertext = in.bytes(1 << 20);
    in.expectEnd();
    try (SymmetricKey key = dataRoot.derive(Purpose.METADATA_MANIFEST, mailboxId.toBytes());
        Secret plaintext = key.open(ciphertext, context(mailboxId, dataVersion, generation))) {
      RecordReader body = new RecordReader(plaintext.exposeCopy());
      OpaqueId snapshot = body.bool() ? body.id() : null;
      long count = body.u32();
      if (count > 100_000) {
        throw new FormatException("too many segments");
      }
      List<OpaqueId> sealedSegments = new ArrayList<>();
      for (long i = 0; i < count; i++) {
        sealedSegments.add(body.id());
      }
      OpaqueId active = body.id();
      body.expectEnd();
      return new Manifest(generation, dataVersion, snapshot, sealedSegments, active);
    }
  }

  private static RecordReader header(byte[] sealed, OpaqueId mailboxId) throws FormatException {
    RecordReader in = new RecordReader(sealed);
    if (!java.util.Arrays.equals(in.raw(4), MAGIC)) {
      throw new FormatException("not a manifest");
    }
    if (in.u8() != FORMAT || in.u8() != CryptoProfile.PROFILE_VERSION) {
      throw new FormatException("unsupported manifest version");
    }
    if (!in.id().equals(mailboxId)) {
      throw new FormatException("manifest belongs to another mailbox");
    }
    return in;
  }

  private static AssociatedData context(OpaqueId mailboxId, int dataVersion, long generation) {
    return AssociatedData.builder(Purpose.METADATA_MANIFEST, FORMAT)
        .id("mailbox", mailboxId)
        .number("dataVersion", dataVersion)
        .number("generation", generation)
        .build();
  }

  static String snapshotFile(OpaqueId snapshotId) {
    return "snap-" + snapshotId.value();
  }

  static AssociatedData snapshotContext(OpaqueId mailboxId, OpaqueId snapshotId) {
    return AssociatedData.builder(Purpose.METADATA_SNAPSHOT, FORMAT)
        .id("mailbox", mailboxId)
        .id("snapshot", snapshotId)
        .build();
  }
}
