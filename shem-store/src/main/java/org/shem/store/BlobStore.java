package org.shem.store;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import org.shem.common.DurableFiles;
import org.shem.common.FaultInjector;
import org.shem.common.IdGenerator;
import org.shem.common.OpaqueId;
import org.shem.crypto.AssociatedData;
import org.shem.crypto.CryptoException;
import org.shem.crypto.CryptoProfile;
import org.shem.crypto.Purpose;
import org.shem.crypto.SymmetricKey;

/**
 * Immutable encrypted message blobs.
 *
 * <p>File format {@code "SHBL", u8 format=1, u8 profile} followed by a Tink AES-256-GCM-HKDF
 * streaming ciphertext under a fresh per-blob content key, with associated data binding mailbox and
 * blob id. The content key never touches disk unwrapped: callers seal it into a receipt or metadata
 * record. Blobs are published only after a complete, synced write.
 */
public final class BlobStore {
  public static final String FAULT_BEFORE_PUBLISH = "blob.before-publish";
  public static final String FAULT_AFTER_PUBLISH = "blob.after-publish";
  private static final byte[] MAGIC = {'S', 'H', 'B', 'L', 1, CryptoProfile.PROFILE_VERSION};
  private static final int FORMAT = 1;

  private final MailboxPaths paths;
  private final IdGenerator ids;
  private final SecureRandom random;
  private final FaultInjector faults;

  public BlobStore(MailboxPaths paths, IdGenerator ids, SecureRandom random, FaultInjector faults) {
    this.paths = paths;
    this.ids = ids;
    this.random = random;
    this.faults = faults;
  }

  /** Result of a durable write. The caller owns {@code contentKey} and must close it. */
  public record WrittenBlob(
      OpaqueId blobId, SymmetricKey contentKey, long plaintextBytes, long ciphertextBytes) {}

  /**
   * Encrypts and durably stores {@code plaintext}, failing with {@link
   * StorageException.Kind#LIMIT_EXCEEDED} (and leaving nothing published) beyond {@code maxBytes}.
   */
  public WrittenBlob write(OpaqueId mailboxId, InputStream plaintext, long maxBytes)
      throws StorageException {
    OpaqueId blobId = ids.next();
    Path target = path(mailboxId, blobId);
    SymmetricKey contentKey = SymmetricKey.generate(random);
    Path temp = null;
    try {
      Path parent = target.getParent();
      if (parent == null) {
        throw new IllegalStateException("blob path has no parent");
      }
      DurableFiles.createPrivateDirectories(parent);
      temp = DurableFiles.createTemporarySibling(target);
      long written = 0;
      try (FileChannel channel = FileChannel.open(temp, StandardOpenOption.WRITE)) {
        OutputStream raw = DurableFiles.syncingOutputStream(channel);
        raw.write(MAGIC);
        try (OutputStream encrypted =
            contentKey
                .streaming(CryptoProfile.BLOB_SEGMENT_BYTES)
                .encrypt(raw, context(mailboxId, blobId))) {
          byte[] buffer = new byte[16 * 1024];
          int n;
          while ((n = plaintext.read(buffer)) > 0) {
            written += n;
            if (written > maxBytes) {
              throw new StorageException(StorageException.Kind.LIMIT_EXCEEDED, "message too large");
            }
            encrypted.write(buffer, 0, n);
          }
          java.util.Arrays.fill(buffer, (byte) 0);
        }
      }
      faults.at(FAULT_BEFORE_PUBLISH);
      DurableFiles.publish(temp, target, false);
      temp = null;
      faults.at(FAULT_AFTER_PUBLISH);
      return new WrittenBlob(blobId, contentKey, written, Files.size(target));
    } catch (StorageException e) {
      contentKey.close();
      throw e;
    } catch (FileAlreadyExistsException e) {
      contentKey.close();
      throw new StorageException(StorageException.Kind.CONFLICT, "blob id collision", e);
    } catch (IOException e) {
      contentKey.close();
      throw new StorageException(StorageException.Kind.UNAVAILABLE, "blob write failed", e);
    } catch (CryptoException e) {
      contentKey.close();
      throw new StorageException(StorageException.Kind.UNAVAILABLE, "blob encryption failed", e);
    } catch (RuntimeException e) {
      contentKey.close();
      throw e;
    } finally {
      if (temp != null) {
        try {
          Files.deleteIfExists(temp);
        } catch (IOException ignored) {
          // Leftover ciphertext-only temp files are reclaimed by the orphan sweep.
        }
      }
    }
  }

  /** Streams verified plaintext; an authentication failure surfaces as an {@link IOException}. */
  public InputStream open(OpaqueId mailboxId, OpaqueId blobId, SymmetricKey contentKey)
      throws StorageException {
    Path file = path(mailboxId, blobId);
    InputStream raw = null;
    try {
      raw = Files.newInputStream(file);
      byte[] header = raw.readNBytes(MAGIC.length);
      if (!java.util.Arrays.equals(header, MAGIC)) {
        throw new StorageException(StorageException.Kind.CORRUPT, "unknown blob format");
      }
      InputStream decrypted =
          contentKey
              .streaming(CryptoProfile.BLOB_SEGMENT_BYTES)
              .decrypt(raw, context(mailboxId, blobId));
      return new CorruptionMappingStream(decrypted);
    } catch (NoSuchFileException e) {
      closeQuietly(raw);
      throw new StorageException(StorageException.Kind.CORRUPT, "referenced blob missing", e);
    } catch (IOException e) {
      closeQuietly(raw);
      throw new StorageException(StorageException.Kind.UNAVAILABLE, "blob read failed", e);
    } catch (CryptoException e) {
      closeQuietly(raw);
      throw new StorageException(StorageException.Kind.CORRUPT, "blob decryption failed", e);
    } catch (StorageException e) {
      closeQuietly(raw);
      throw e;
    }
  }

  /** Random-access plaintext view for range reads; {@code size()} is the plaintext length. */
  public SeekableByteChannel openSeekable(OpaqueId mailboxId, OpaqueId blobId, SymmetricKey key)
      throws StorageException {
    Path file = path(mailboxId, blobId);
    FileChannel channel = null;
    try {
      channel = FileChannel.open(file, StandardOpenOption.READ);
      java.nio.ByteBuffer header = java.nio.ByteBuffer.allocate(MAGIC.length);
      while (header.hasRemaining() && channel.read(header) > 0) {}
      if (!java.util.Arrays.equals(header.array(), MAGIC)) {
        throw new StorageException(StorageException.Kind.CORRUPT, "unknown blob format");
      }
      return key.streaming(CryptoProfile.BLOB_SEGMENT_BYTES)
          .decryptSeekable(new OffsetChannel(channel, MAGIC.length), context(mailboxId, blobId));
    } catch (NoSuchFileException e) {
      closeQuietly(channel);
      throw new StorageException(StorageException.Kind.CORRUPT, "referenced blob missing", e);
    } catch (IOException e) {
      closeQuietly(channel);
      throw new StorageException(StorageException.Kind.CORRUPT, "blob read failed", e);
    } catch (CryptoException e) {
      closeQuietly(channel);
      throw new StorageException(StorageException.Kind.CORRUPT, "blob decryption failed", e);
    } catch (StorageException e) {
      closeQuietly(channel);
      throw e;
    }
  }

  public boolean exists(OpaqueId mailboxId, OpaqueId blobId) {
    return Files.isRegularFile(path(mailboxId, blobId));
  }

  public long ciphertextSize(OpaqueId mailboxId, OpaqueId blobId) throws StorageException {
    try {
      return Files.size(path(mailboxId, blobId));
    } catch (IOException e) {
      throw new StorageException(StorageException.Kind.NOT_FOUND, "blob missing", e);
    }
  }

  public long lastModifiedMillis(OpaqueId mailboxId, OpaqueId blobId) throws StorageException {
    try {
      return Files.getLastModifiedTime(path(mailboxId, blobId)).toMillis();
    } catch (IOException e) {
      throw new StorageException(StorageException.Kind.NOT_FOUND, "blob missing", e);
    }
  }

  /** Removes a blob; returns the freed ciphertext bytes (0 if already absent). */
  public long delete(OpaqueId mailboxId, OpaqueId blobId) throws StorageException {
    Path file = path(mailboxId, blobId);
    try {
      long size = Files.exists(file) ? Files.size(file) : 0;
      DurableFiles.deleteDurably(file);
      return size;
    } catch (IOException e) {
      throw new StorageException(StorageException.Kind.UNAVAILABLE, "blob delete failed", e);
    }
  }

  /** All committed blob ids of a mailbox (excludes temporary files). */
  public List<OpaqueId> list(OpaqueId mailboxId) throws StorageException {
    List<OpaqueId> result = new ArrayList<>();
    Path root = paths.blobs(mailboxId);
    if (!Files.isDirectory(root)) {
      return result;
    }
    try (var shards = Files.walk(root, 3)) {
      for (Path file : (Iterable<Path>) shards::iterator) {
        if (Files.isRegularFile(file)) {
          OpaqueId id = OpaqueId.parseOrNull(String.valueOf(file.getFileName()));
          if (id != null) {
            result.add(id);
          }
        }
      }
    } catch (IOException e) {
      throw new StorageException(StorageException.Kind.UNAVAILABLE, "blob listing failed", e);
    }
    return result;
  }

  /** Deletes abandoned ciphertext-only temporary files left by crashes. */
  public int sweepTemporaryFiles(OpaqueId mailboxId) throws StorageException {
    int removed = 0;
    Path root = paths.blobs(mailboxId);
    if (!Files.isDirectory(root)) {
      return 0;
    }
    try (var files = Files.walk(root, 3)) {
      for (Path file : (Iterable<Path>) files::iterator) {
        if (String.valueOf(file.getFileName()).startsWith(DurableFiles.TEMP_PREFIX)) {
          Files.deleteIfExists(file);
          removed++;
        }
      }
    } catch (IOException e) {
      throw new StorageException(StorageException.Kind.UNAVAILABLE, "temp sweep failed", e);
    }
    return removed;
  }

  Path path(OpaqueId mailboxId, OpaqueId blobId) {
    return paths.blobs(mailboxId).resolve(blobId.shardPath()).resolve(blobId.value());
  }

  static AssociatedData context(OpaqueId mailboxId, OpaqueId blobId) {
    return AssociatedData.builder(Purpose.MESSAGE_BLOB, FORMAT)
        .id("mailbox", mailboxId)
        .id("blob", blobId)
        .build();
  }

  private static void closeQuietly(@org.jspecify.annotations.Nullable AutoCloseable closeable) {
    if (closeable != null) {
      try {
        closeable.close();
      } catch (Exception ignored) {
        // Closing after a failure; the original failure is reported.
      }
    }
  }

  /** Marks authentication failures so callers can distinguish corruption from I/O errors. */
  public static final class BlobCorruptedException extends IOException {
    private static final long serialVersionUID = 1L;

    BlobCorruptedException(IOException cause) {
      super("blob failed authentication", cause);
    }
  }

  private static final class CorruptionMappingStream extends FilterInputStream {
    CorruptionMappingStream(InputStream in) {
      super(in);
    }

    @Override
    public int read() throws IOException {
      try {
        return super.read();
      } catch (IOException e) {
        throw new BlobCorruptedException(e);
      }
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
      try {
        return super.read(b, off, len);
      } catch (IOException e) {
        throw new BlobCorruptedException(e);
      }
    }
  }

  /** Exposes a file channel without its first {@code offset} bytes. */
  static final class OffsetChannel implements SeekableByteChannel {
    private final FileChannel channel;
    private final long offset;

    OffsetChannel(FileChannel channel, long offset) {
      this.channel = channel;
      this.offset = offset;
    }

    @Override
    public int read(java.nio.ByteBuffer dst) throws IOException {
      return channel.read(dst);
    }

    @Override
    public int write(java.nio.ByteBuffer src) throws IOException {
      throw new IOException("read-only");
    }

    @Override
    public long position() throws IOException {
      return channel.position() - offset;
    }

    @Override
    public SeekableByteChannel position(long newPosition) throws IOException {
      channel.position(newPosition + offset);
      return this;
    }

    @Override
    public long size() throws IOException {
      return channel.size() - offset;
    }

    @Override
    public SeekableByteChannel truncate(long size) throws IOException {
      throw new IOException("read-only");
    }

    @Override
    public boolean isOpen() {
      return channel.isOpen();
    }

    @Override
    public void close() throws IOException {
      channel.close();
    }
  }
}
