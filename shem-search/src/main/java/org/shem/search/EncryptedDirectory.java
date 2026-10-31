package org.shem.search;

import java.io.EOFException;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.util.Arrays;
import java.util.Collection;
import java.util.concurrent.ConcurrentHashMap;
import java.util.zip.CRC32;
import org.apache.lucene.store.BufferedIndexInput;
import org.apache.lucene.store.Directory;
import org.apache.lucene.store.FilterDirectory;
import org.apache.lucene.store.IOContext;
import org.apache.lucene.store.IndexInput;
import org.apache.lucene.store.IndexOutput;
import org.shem.common.OpaqueId;
import org.shem.crypto.AssociatedData;
import org.shem.crypto.CryptoException;
import org.shem.crypto.CryptoProfile;
import org.shem.crypto.Purpose;
import org.shem.crypto.StreamingCipher;
import org.shem.crypto.SymmetricKey;

/**
 * Lucene {@link Directory} whose files are authenticated streaming-AEAD ciphertext (Tink
 * AES-256-GCM-HKDF, 16 KiB segments, fresh per-file key from a random salt). Associated data binds
 * mailbox and file name, so files cannot be swapped, truncated, reordered, or edited without an
 * {@link IOException} on read. Random access decrypts only the segments touched; nothing is
 * memory-mapped and no plaintext reaches disk.
 *
 * <p>Lucene's commit renames {@code pending_segments_N} to {@code segments_N}; because the name is
 * authenticated, {@link #rename} re-encrypts the (small) file under the destination name into a
 * temporary file and then renames that atomically. Lucene file names (codec and segment names)
 * remain visible; terms and field names are only inside ciphertext.
 */
public final class EncryptedDirectory extends FilterDirectory {
  private static final byte[] MAGIC = {'S', 'H', 'I', 'X', 1, CryptoProfile.PROFILE_VERSION};
  private static final int FORMAT = 1;
  static final String RENAME_PREFIX = "shem-rename";

  private final StreamingCipher cipher;
  private final OpaqueId mailboxId;
  private final ConcurrentHashMap<String, Long> lengths = new ConcurrentHashMap<>();

  /** Wraps {@code delegate} (which must not memory-map); uses but does not keep {@code key}. */
  public EncryptedDirectory(Directory delegate, SymmetricKey key, OpaqueId mailboxId)
      throws CryptoException, IOException {
    super(delegate);
    this.cipher = key.streaming(CryptoProfile.FILE_SEGMENT_BYTES);
    this.mailboxId = mailboxId;
    for (String name : delegate.listAll()) {
      if (name.startsWith(RENAME_PREFIX)) {
        delegate.deleteFile(name);
      }
    }
  }

  private AssociatedData context(String name) {
    return AssociatedData.builder(Purpose.SEARCH_INDEX, FORMAT)
        .id("mailbox", mailboxId)
        .text("file", name)
        .build();
  }

  @Override
  public IndexOutput createOutput(String name, IOContext context) throws IOException {
    return encrypting(name, in.createOutput(name, context));
  }

  @Override
  public IndexOutput createTempOutput(String prefix, String suffix, IOContext context)
      throws IOException {
    IndexOutput raw = in.createTempOutput(prefix, suffix, context);
    return encrypting(raw.getName(), raw);
  }

  private IndexOutput encrypting(String authenticatedName, IndexOutput raw) throws IOException {
    try {
      raw.writeBytes(MAGIC, MAGIC.length);
      return new EncryptingOutput(raw.getName(), authenticatedName, raw);
    } catch (IOException | RuntimeException e) {
      raw.close();
      throw e;
    }
  }

  @Override
  public IndexInput openInput(String name, IOContext context) throws IOException {
    IndexInput raw = in.openInput(name, context);
    try {
      byte[] header = new byte[MAGIC.length];
      if (raw.length() < MAGIC.length) {
        throw new EOFException("index file too short: " + name);
      }
      raw.readBytes(header, 0, header.length);
      if (!Arrays.equals(header, MAGIC)) {
        throw new IOException("not an encrypted index file: " + name);
      }
      SeekableByteChannel channel;
      try {
        channel = cipher.decryptSeekable(new RawChannel(raw), context(name));
      } catch (CryptoException e) {
        throw new IOException("index file failed authentication: " + name, e);
      }
      long length = channel.size();
      lengths.putIfAbsent(name, length);
      return new DecryptingInput(
          "EncryptedDirectory(" + name + ")", new Shared(channel, raw), 0, length, false);
    } catch (IOException | RuntimeException e) {
      raw.close();
      throw e;
    }
  }

  @Override
  public long fileLength(String name) throws IOException {
    Long cached = lengths.get(name);
    if (cached != null) {
      return cached;
    }
    try (IndexInput input = openInput(name, IOContext.READONCE)) {
      return input.length();
    }
  }

  @Override
  public void deleteFile(String name) throws IOException {
    lengths.remove(name);
    in.deleteFile(name);
  }

  @Override
  public void rename(String source, String dest) throws IOException {
    IndexOutput raw = in.createTempOutput(RENAME_PREFIX, "tmp", IOContext.DEFAULT);
    String temp = raw.getName();
    try {
      try (IndexInput input = openInput(source, IOContext.READONCE);
          IndexOutput output = encrypting(dest, raw)) {
        byte[] buffer = new byte[8192];
        long remaining = input.length();
        while (remaining > 0) {
          int n = (int) Math.min(buffer.length, remaining);
          input.readBytes(buffer, 0, n);
          output.writeBytes(buffer, n);
          remaining -= n;
        }
      }
      in.sync(java.util.List.of(temp));
      in.rename(temp, dest);
      temp = null;
      lengths.remove(dest);
      deleteFile(source);
    } finally {
      if (temp != null) {
        in.deleteFile(temp);
      }
    }
  }

  @Override
  public void sync(Collection<String> names) throws IOException {
    in.sync(names);
  }

  /** IndexOutput encrypting into the raw output; checksum and pointer refer to plaintext. */
  private final class EncryptingOutput extends IndexOutput {
    private final IndexOutput raw;
    private final OutputStream encrypted;
    private final CRC32 crc = new CRC32();
    private long pointer;
    private boolean closed;

    EncryptingOutput(String name, String authenticatedName, IndexOutput raw) throws IOException {
      super("EncryptedDirectory(" + name + ")", name);
      this.raw = raw;
      try {
        this.encrypted = cipher.encrypt(new RawOutputStream(raw), context(authenticatedName));
      } catch (CryptoException e) {
        throw new IOException("index encryption setup failed", e);
      }
    }

    @Override
    public void writeByte(byte b) throws IOException {
      encrypted.write(b);
      crc.update(b);
      pointer++;
    }

    @Override
    public void writeBytes(byte[] b, int offset, int length) throws IOException {
      encrypted.write(b, offset, length);
      crc.update(b, offset, length);
      pointer += length;
    }

    @Override
    public long getFilePointer() {
      return pointer;
    }

    @Override
    public long getChecksum() {
      return crc.getValue();
    }

    @Override
    public void close() throws IOException {
      if (closed) {
        return;
      }
      closed = true;
      try {
        encrypted.close();
      } finally {
        raw.close();
      }
    }
  }

  /** OutputStream view of a raw IndexOutput (ciphertext). */
  private static final class RawOutputStream extends OutputStream {
    private final IndexOutput raw;

    RawOutputStream(IndexOutput raw) {
      this.raw = raw;
    }

    @Override
    public void write(int b) throws IOException {
      raw.writeByte((byte) b);
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
      raw.writeBytes(b, off, len);
    }

    @Override
    public void close() {
      // The raw output is closed by EncryptingOutput after the final segment is written.
    }
  }

  /** Read-only seekable channel over the ciphertext part of a raw IndexInput. */
  private static final class RawChannel implements SeekableByteChannel {
    private final IndexInput raw;
    private long position;

    RawChannel(IndexInput raw) {
      this.raw = raw;
    }

    @Override
    public int read(ByteBuffer dst) throws IOException {
      long available = size() - position;
      if (available <= 0) {
        return -1;
      }
      int n = (int) Math.min(dst.remaining(), available);
      byte[] bytes = new byte[n];
      raw.seek(MAGIC.length + position);
      raw.readBytes(bytes, 0, n);
      dst.put(bytes);
      position += n;
      return n;
    }

    @Override
    public int write(ByteBuffer src) throws IOException {
      throw new IOException("read-only");
    }

    @Override
    public long position() {
      return position;
    }

    @Override
    public SeekableByteChannel position(long newPosition) {
      position = newPosition;
      return this;
    }

    @Override
    public long size() {
      return raw.length() - MAGIC.length;
    }

    @Override
    public SeekableByteChannel truncate(long size) throws IOException {
      throw new IOException("read-only");
    }

    @Override
    public boolean isOpen() {
      return true;
    }

    @Override
    public void close() throws IOException {
      raw.close();
    }
  }

  /** Decrypting channel shared by an input and its clones and slices. */
  private record Shared(SeekableByteChannel channel, IndexInput raw) {
    void read(long position, ByteBuffer dst) throws IOException {
      synchronized (this) {
        channel.position(position);
        while (dst.hasRemaining()) {
          if (channel.read(dst) < 0) {
            throw new EOFException("read past end of index file");
          }
        }
      }
    }
  }

  private static final class DecryptingInput extends BufferedIndexInput {
    private final Shared shared;
    private final long offset;
    private final long length;
    private boolean isClone;

    DecryptingInput(String description, Shared shared, long offset, long length, boolean isClone) {
      super(description, BufferedIndexInput.BUFFER_SIZE);
      this.shared = shared;
      this.offset = offset;
      this.length = length;
      this.isClone = isClone;
    }

    @Override
    protected void readInternal(ByteBuffer b) throws IOException {
      long position = getFilePointer();
      if (position + b.remaining() > length) {
        throw new EOFException("read past EOF: " + this);
      }
      shared.read(offset + position, b);
    }

    @Override
    protected void seekInternal(long pos) throws IOException {
      if (pos > length) {
        throw new EOFException("seek past EOF: " + this);
      }
    }

    @Override
    public long length() {
      return length;
    }

    @Override
    public DecryptingInput clone() {
      DecryptingInput clone = (DecryptingInput) super.clone();
      clone.isClone = true;
      return clone;
    }

    @Override
    public IndexInput slice(String description, long sliceOffset, long sliceLength)
        throws IOException {
      if (sliceOffset < 0 || sliceLength < 0 || sliceOffset + sliceLength > length) {
        throw new IllegalArgumentException("slice out of bounds: " + description);
      }
      return new DecryptingInput(
          getFullSliceDescription(description), shared, offset + sliceOffset, sliceLength, true);
    }

    @Override
    public void close() throws IOException {
      if (!isClone) {
        synchronized (shared) {
          shared.channel().close();
          shared.raw().close();
        }
      }
    }
  }
}
