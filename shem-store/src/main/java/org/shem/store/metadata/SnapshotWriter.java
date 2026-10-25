package org.shem.store.metadata;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.shem.common.DurableFiles;
import org.shem.common.ImmutableBytes;
import org.shem.common.OpaqueId;
import org.shem.common.RecordWriter;
import org.shem.crypto.AssociatedData;
import org.shem.crypto.CryptoException;
import org.shem.crypto.CryptoProfile;
import org.shem.crypto.SymmetricKey;

/**
 * Writes an immutable snapshot: header tables, sorted message blocks, a block index, and a fixed
 * trailer, all inside one streaming-AEAD ciphertext (seekable for block lookups).
 */
final class SnapshotWriter {
  static final byte[] START = {'S', 'N', 'P', 'S', 1};
  static final byte[] END = {'S', 'N', 'P', 'E'};
  static final int TRAILER_BYTES = 4 + 4 * 8;
  static final int BLOCK_ENTRIES = 128;
  static final int BLOCK_BYTES = 64 * 1024;

  private SnapshotWriter() {}

  record BlockIndexEntry(MessageKey first, MessageKey last, long offset, int length, int count) {}

  /** Writes and durably publishes a snapshot; entries must be sorted and tombstone-free. */
  static void write(
      Path target,
      SymmetricKey fileKey,
      AssociatedData context,
      long txSeq,
      MailboxState tables,
      Iterator<Map.Entry<MessageKey, MessageRecord>> entries)
      throws IOException, CryptoException {
    Path temp = DurableFiles.createTemporarySibling(target);
    try {
      try (FileChannel channel = FileChannel.open(temp, StandardOpenOption.WRITE);
          OutputStream raw = DurableFiles.syncingOutputStream(channel);
          OutputStream encrypted =
              fileKey.streaming(CryptoProfile.FILE_SEGMENT_BYTES).encrypt(raw, context)) {
        CountingOutput out = new CountingOutput(encrypted);
        out.write(START);
        long headerOffset = out.count;
        out.write(header(txSeq, tables));
        long headerLength = out.count - headerOffset;
        List<BlockIndexEntry> index = new ArrayList<>();
        RecordWriter block = new RecordWriter();
        List<MessageKey> keys = new ArrayList<>();
        while (entries.hasNext()) {
          Map.Entry<MessageKey, MessageRecord> entry = entries.next();
          Codec.key(block, entry.getKey());
          Codec.record(block, entry.getValue());
          keys.add(entry.getKey());
          if (keys.size() >= BLOCK_ENTRIES || block.size() >= BLOCK_BYTES) {
            index.add(flush(out, block, keys));
            block = new RecordWriter();
            keys.clear();
          }
        }
        if (!keys.isEmpty()) {
          index.add(flush(out, block, keys));
        }
        long indexOffset = out.count;
        RecordWriter indexOut = new RecordWriter().u32(index.size());
        for (BlockIndexEntry e : index) {
          Codec.key(indexOut, e.first());
          Codec.key(indexOut, e.last());
          indexOut.i64(e.offset()).u32(e.length()).u32(e.count());
        }
        out.write(indexOut.toByteArray());
        long indexLength = out.count - indexOffset;
        out.write(
            new RecordWriter()
                .raw(END)
                .i64(headerOffset)
                .i64(headerLength)
                .i64(indexOffset)
                .i64(indexLength)
                .toByteArray());
      }
      DurableFiles.publish(temp, target, false);
    } finally {
      java.nio.file.Files.deleteIfExists(temp);
    }
  }

  private static BlockIndexEntry flush(
      CountingOutput out, RecordWriter block, List<MessageKey> keys) throws IOException {
    long offset = out.count;
    byte[] body = new RecordWriter().u32(keys.size()).raw(block.toByteArray()).toByteArray();
    out.write(body);
    return new BlockIndexEntry(
        keys.get(0), keys.get(keys.size() - 1), offset, body.length, keys.size());
  }

  private static byte[] header(long txSeq, MailboxState s) {
    RecordWriter out = new RecordWriter().i64(txSeq).i64(s.modSeq);
    out.u32(s.folders.size());
    s.folders.values().stream()
        .sorted(java.util.Comparator.comparing(Folder::folderId))
        .forEach(f -> Codec.folder(out, f));
    out.u32(s.subscriptions.size());
    s.subscriptions.forEach(out::string);
    out.u32(s.properties.size());
    for (Map.Entry<String, ImmutableBytes> p : s.properties.entrySet()) {
      out.string(p.getKey()).bytes(p.getValue().toByteArray());
    }
    out.u32(s.importedReceipts.size());
    for (Map.Entry<OpaqueId, Long> r : s.importedReceipts.entrySet()) {
      out.id(r.getKey()).i64(r.getValue());
    }
    return out.toByteArray();
  }

  private static final class CountingOutput {
    private final OutputStream out;
    long count;

    CountingOutput(OutputStream out) {
      this.out = out;
    }

    void write(byte[] data) throws IOException {
      out.write(data);
      count += data.length;
    }
  }
}
