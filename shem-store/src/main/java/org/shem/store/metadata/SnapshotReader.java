package org.shem.store.metadata;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;
import org.shem.common.FormatException;
import org.shem.common.ImmutableBytes;
import org.shem.common.RecordReader;
import org.shem.crypto.AssociatedData;
import org.shem.crypto.CryptoException;
import org.shem.crypto.CryptoProfile;
import org.shem.crypto.SymmetricKey;
import org.shem.store.StorageException;

/**
 * Random-access reader for a snapshot with a bounded LRU cache of decoded blocks. Only header
 * tables and the block index are loaded eagerly; message blocks load on demand.
 */
final class SnapshotReader implements AutoCloseable {
  private final SeekableByteChannel channel;
  private final List<SnapshotWriter.BlockIndexEntry> index;
  private final Map<Integer, List<Map.Entry<MessageKey, MessageRecord>>> cache;
  final long txSeq;
  final MailboxState tables = new MailboxState();

  private SnapshotReader(
      SeekableByteChannel channel,
      List<SnapshotWriter.BlockIndexEntry> index,
      long txSeq,
      int cacheBlocks) {
    this.channel = channel;
    this.index = index;
    this.txSeq = txSeq;
    this.cache =
        new LinkedHashMap<>(16, 0.75f, true) {
          private static final long serialVersionUID = 1L;

          @Override
          protected boolean removeEldestEntry(
              Map.Entry<Integer, List<Map.Entry<MessageKey, MessageRecord>>> eldest) {
            return size() > cacheBlocks;
          }
        };
  }

  static SnapshotReader open(
      Path file, SymmetricKey fileKey, AssociatedData context, int cacheBlocks)
      throws StorageException {
    FileChannel raw = null;
    SeekableByteChannel channel = null;
    try {
      raw = FileChannel.open(file, StandardOpenOption.READ);
      channel = fileKey.streaming(CryptoProfile.FILE_SEGMENT_BYTES).decryptSeekable(raw, context);
      long size = channel.size();
      if (size < SnapshotWriter.START.length + SnapshotWriter.TRAILER_BYTES) {
        throw new FormatException("snapshot too short");
      }
      if (!java.util.Arrays.equals(
          read(channel, 0, SnapshotWriter.START.length), SnapshotWriter.START)) {
        throw new FormatException("not a snapshot");
      }
      RecordReader trailer =
          new RecordReader(
              read(channel, size - SnapshotWriter.TRAILER_BYTES, SnapshotWriter.TRAILER_BYTES));
      if (!java.util.Arrays.equals(trailer.raw(4), SnapshotWriter.END)) {
        throw new FormatException("snapshot trailer missing");
      }
      long headerOffset = trailer.i64();
      long headerLength = trailer.i64();
      long indexOffset = trailer.i64();
      long indexLength = trailer.i64();
      if (headerLength > Integer.MAX_VALUE
          || indexLength > Integer.MAX_VALUE
          || indexOffset + indexLength != size - SnapshotWriter.TRAILER_BYTES) {
        throw new FormatException("snapshot layout invalid");
      }
      RecordReader indexIn = new RecordReader(read(channel, indexOffset, (int) indexLength));
      long blocks = indexIn.u32();
      List<SnapshotWriter.BlockIndexEntry> index = new ArrayList<>();
      for (long i = 0; i < blocks; i++) {
        index.add(
            new SnapshotWriter.BlockIndexEntry(
                Codec.key(indexIn),
                Codec.key(indexIn),
                indexIn.i64(),
                (int) indexIn.u32(),
                (int) indexIn.u32()));
      }
      indexIn.expectEnd();
      RecordReader header = new RecordReader(read(channel, headerOffset, (int) headerLength));
      SnapshotReader reader = new SnapshotReader(channel, index, header.i64(), cacheBlocks);
      MailboxState t = reader.tables;
      t.modSeq = header.i64();
      for (long i = 0, n = header.u32(); i < n; i++) {
        Folder f = Codec.folder(header);
        t.folders.put(f.folderId(), f);
      }
      for (long i = 0, n = header.u32(); i < n; i++) {
        t.subscriptions.add(header.string(Folder.MAX_NAME_BYTES));
      }
      for (long i = 0, n = header.u32(); i < n; i++) {
        t.properties.put(
            header.string(Codec.MAX_TEXT), ImmutableBytes.copyOf(header.bytes(Codec.MAX_BYTES)));
      }
      for (long i = 0, n = header.u32(); i < n; i++) {
        t.importedReceipts.put(header.id(), header.i64());
      }
      header.expectEnd();
      t.txSeq = reader.txSeq;
      return reader;
    } catch (FormatException e) {
      closeQuietly(channel, raw);
      throw new StorageException(StorageException.Kind.CORRUPT, "snapshot malformed", e);
    } catch (CryptoException | IOException e) {
      closeQuietly(channel, raw);
      throw new StorageException(StorageException.Kind.CORRUPT, "snapshot failed verification", e);
    }
  }

  Optional<MessageRecord> lookup(MessageKey key) {
    int lo = 0;
    int hi = index.size() - 1;
    while (lo <= hi) {
      int mid = (lo + hi) >>> 1;
      SnapshotWriter.BlockIndexEntry entry = index.get(mid);
      if (key.compareTo(entry.first()) < 0) {
        hi = mid - 1;
      } else if (key.compareTo(entry.last()) > 0) {
        lo = mid + 1;
      } else {
        for (Map.Entry<MessageKey, MessageRecord> e : block(mid)) {
          if (e.getKey().equals(key)) {
            return Optional.of(e.getValue());
          }
        }
        return Optional.empty();
      }
    }
    return Optional.empty();
  }

  /** Entries with keys in [from, to], in order, loading blocks lazily. */
  Iterator<Map.Entry<MessageKey, MessageRecord>> range(MessageKey from, MessageKey to) {
    int start = 0;
    while (start < index.size() && index.get(start).last().compareTo(from) < 0) {
      start++;
    }
    int firstBlock = start;
    return new Iterator<>() {
      int blockNo = firstBlock;
      int position;
      List<Map.Entry<MessageKey, MessageRecord>> current = List.of();
      Map.@org.jspecify.annotations.Nullable Entry<MessageKey, MessageRecord> next = advance();

      private Map.@org.jspecify.annotations.Nullable Entry<MessageKey, MessageRecord> advance() {
        while (true) {
          if (position < current.size()) {
            Map.Entry<MessageKey, MessageRecord> e = current.get(position++);
            if (e.getKey().compareTo(from) < 0) {
              continue;
            }
            return e.getKey().compareTo(to) <= 0 ? e : null;
          }
          if (blockNo >= index.size() || index.get(blockNo).first().compareTo(to) > 0) {
            return null;
          }
          current = block(blockNo++);
          position = 0;
        }
      }

      @Override
      public boolean hasNext() {
        return next != null;
      }

      @Override
      public Map.Entry<MessageKey, MessageRecord> next() {
        if (!hasNext()) {
          throw new NoSuchElementException();
        }
        Map.Entry<MessageKey, MessageRecord> result = next;
        if (result == null) {
          throw new NoSuchElementException();
        }
        next = advance();
        return result;
      }
    };
  }

  long blockCount() {
    return index.size();
  }

  private synchronized List<Map.Entry<MessageKey, MessageRecord>> block(int blockNo) {
    List<Map.Entry<MessageKey, MessageRecord>> cached = cache.get(blockNo);
    if (cached != null) {
      return cached;
    }
    SnapshotWriter.BlockIndexEntry entry = index.get(blockNo);
    try {
      RecordReader in = new RecordReader(read(channel, entry.offset(), entry.length()));
      long count = in.u32();
      if (count != entry.count()) {
        throw new FormatException("block count mismatch");
      }
      List<Map.Entry<MessageKey, MessageRecord>> entries = new ArrayList<>((int) count);
      for (long i = 0; i < count; i++) {
        entries.add(Map.entry(Codec.key(in), Codec.record(in)));
      }
      in.expectEnd();
      List<Map.Entry<MessageKey, MessageRecord>> immutable = List.copyOf(entries);
      cache.put(blockNo, immutable);
      return immutable;
    } catch (FormatException | IOException e) {
      // Authenticated data that fails to decode is corruption; never return a partial view.
      throw new CorruptSnapshotException(e);
    }
  }

  /** Unchecked wrapper so iteration can surface corruption; the store converts it. */
  static final class CorruptSnapshotException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    CorruptSnapshotException(Exception cause) {
      super("snapshot block failed verification", cause);
    }
  }

  private static byte[] read(SeekableByteChannel channel, long position, int length)
      throws IOException {
    ByteBuffer buffer = ByteBuffer.allocate(length);
    synchronized (channel) {
      channel.position(position);
      while (buffer.hasRemaining()) {
        if (channel.read(buffer) < 0) {
          throw new IOException("unexpected end of snapshot");
        }
      }
    }
    return buffer.array();
  }

  @Override
  public synchronized void close() {
    cache.clear();
    closeQuietly(channel, null);
  }

  private static void closeQuietly(
      @org.jspecify.annotations.Nullable AutoCloseable a,
      @org.jspecify.annotations.Nullable AutoCloseable b) {
    for (AutoCloseable c : new AutoCloseable[] {a, b}) {
      if (c != null) {
        try {
          c.close();
        } catch (Exception ignored) {
          // Already failing or closing.
        }
      }
    }
  }
}
