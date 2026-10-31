package org.shem.store.metadata;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import org.shem.common.DurableFiles;
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
 * Journal segments: {@code "SHJS", u8 format, u8 profile, id mailbox, id segment, u32 dataVersion}
 * followed by records {@code u32 length, aesGcm(segmentKey, payload)}. The segment key is derived
 * per segment; each record's associated data binds mailbox, segment, and record index, so records
 * cannot be dropped, reordered, or moved between segments without detection.
 */
final class Journal {
  static final int FORMAT = 1;
  static final int MAX_RECORD = 32 * 1024 * 1024;
  private static final byte[] MAGIC = {'S', 'H', 'J', 'S'};
  static final int TYPE_TX = 1;
  static final int TYPE_SEAL = 2;

  private Journal() {}

  static String fileName(OpaqueId segmentId) {
    return "seg-" + segmentId.value();
  }

  static SymmetricKey segmentKey(SymmetricKey dataRoot, OpaqueId segmentId) throws CryptoException {
    return dataRoot.derive(Purpose.METADATA_JOURNAL, segmentId.toBytes());
  }

  static AssociatedData recordContext(OpaqueId mailboxId, OpaqueId segmentId, long index) {
    return AssociatedData.builder(Purpose.METADATA_JOURNAL, FORMAT)
        .id("mailbox", mailboxId)
        .id("segment", segmentId)
        .number("record", index)
        .build();
  }

  static byte[] header(OpaqueId mailboxId, OpaqueId segmentId, int dataVersion) {
    return new RecordWriter()
        .raw(MAGIC)
        .u8(FORMAT)
        .u8(CryptoProfile.PROFILE_VERSION)
        .id(mailboxId)
        .id(segmentId)
        .u32(dataVersion)
        .toByteArray();
  }

  static int headerLength() {
    return 4 + 2 + 16 + 16 + 4;
  }

  /** Result of reading a segment. */
  record Contents(List<byte[]> payloads, long validLength, boolean sealed, boolean tornTail) {}

  /**
   * Reads and authenticates all records. A final record that extends past end-of-file is a torn
   * write and is reported via {@code tornTail}; any complete record that fails authentication is
   * corruption.
   */
  static Contents read(
      Path file, OpaqueId mailboxId, OpaqueId segmentId, int dataVersion, SymmetricKey dataRoot)
      throws IOException, FormatException, CryptoException {
    byte[] data = Files.readAllBytes(file);
    if (data.length < headerLength()
        || !java.util.Arrays.equals(
            java.util.Arrays.copyOf(data, headerLength()),
            header(mailboxId, segmentId, dataVersion))) {
      throw new FormatException("journal segment header mismatch");
    }
    List<byte[]> payloads = new ArrayList<>();
    boolean sealed = false;
    int position = headerLength();
    try (SymmetricKey key = segmentKey(dataRoot, segmentId)) {
      while (position < data.length) {
        if (sealed) {
          throw new FormatException("data after seal record");
        }
        if (data.length - position < 4) {
          return new Contents(payloads, position, false, true);
        }
        long length =
            new RecordReader(java.util.Arrays.copyOfRange(data, position, position + 4)).u32();
        if (length > MAX_RECORD + 28) {
          throw new FormatException("journal record too large");
        }
        if (data.length - position - 4 < length) {
          return new Contents(payloads, position, false, true);
        }
        byte[] ciphertext =
            java.util.Arrays.copyOfRange(data, position + 4, position + 4 + (int) length);
        try (Secret plaintext =
            key.open(ciphertext, recordContext(mailboxId, segmentId, payloads.size()))) {
          byte[] payload = plaintext.exposeCopy();
          if (payload.length > 0 && payload[0] == TYPE_SEAL) {
            RecordReader seal = new RecordReader(payload);
            seal.u8();
            if (seal.u32() != payloads.size()) {
              throw new FormatException("seal record count mismatch");
            }
            seal.expectEnd();
            sealed = true;
          } else {
            payloads.add(payload);
          }
        }
        position += 4 + (int) length;
      }
    }
    return new Contents(payloads, position, sealed, false);
  }

  /** Appends authenticated records to the active segment, syncing each one. */
  static final class Writer implements AutoCloseable {
    private final FileChannel channel;
    private final OpaqueId mailboxId;
    private final OpaqueId segmentId;
    private final SymmetricKey key;
    private long records;
    private long length;

    private Writer(
        FileChannel channel,
        OpaqueId mailboxId,
        OpaqueId segmentId,
        SymmetricKey key,
        long records,
        long length) {
      this.channel = channel;
      this.mailboxId = mailboxId;
      this.segmentId = segmentId;
      this.key = key;
      this.records = records;
      this.length = length;
    }

    static Writer create(
        Path file, OpaqueId mailboxId, OpaqueId segmentId, int dataVersion, SymmetricKey dataRoot)
        throws IOException, CryptoException {
      DurableFiles.writeNew(file, header(mailboxId, segmentId, dataVersion));
      return reopen(file, mailboxId, segmentId, dataRoot, 0, headerLength());
    }

    /** Reopens after recovery, discarding any torn tail beyond {@code validLength}. */
    static Writer reopen(
        Path file,
        OpaqueId mailboxId,
        OpaqueId segmentId,
        SymmetricKey dataRoot,
        long records,
        long validLength)
        throws IOException, CryptoException {
      FileChannel channel =
          FileChannel.open(file, StandardOpenOption.WRITE, StandardOpenOption.READ);
      try {
        if (channel.size() > validLength) {
          channel.truncate(validLength);
          channel.force(true);
        }
        channel.position(validLength);
        return new Writer(
            channel, mailboxId, segmentId, segmentKey(dataRoot, segmentId), records, validLength);
      } catch (IOException | CryptoException | RuntimeException e) {
        channel.close();
        throw e;
      }
    }

    OpaqueId segmentId() {
      return segmentId;
    }

    long length() {
      return length;
    }

    /** Durably appends one record; on failure the partial bytes are truncated away. */
    void append(byte[] payload) throws IOException, CryptoException {
      byte[] ciphertext = key.seal(payload, recordContext(mailboxId, segmentId, records));
      ByteBuffer buffer =
          ByteBuffer.wrap(new RecordWriter().u32(ciphertext.length).raw(ciphertext).toByteArray());
      try {
        while (buffer.hasRemaining()) {
          channel.write(buffer);
        }
        channel.force(true);
      } catch (IOException e) {
        try {
          channel.truncate(length);
          channel.position(length);
        } catch (IOException suppressed) {
          e.addSuppressed(suppressed);
        }
        throw e;
      }
      records++;
      length += buffer.capacity();
    }

    void seal() throws IOException, CryptoException {
      append(new RecordWriter().u8(TYPE_SEAL).u32(records).toByteArray());
    }

    @Override
    public void close() throws IOException {
      key.close();
      channel.close();
    }
  }
}
