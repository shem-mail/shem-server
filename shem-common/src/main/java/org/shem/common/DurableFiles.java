package org.shem.common;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Set;

/**
 * Durability primitives for the supported filesystems (Linux ext4/xfs with POSIX permissions).
 *
 * <p>Publication protocol: write to an exclusive temporary name in the target directory, {@code
 * fsync} the file, atomically rename, then {@code fsync} the directory. Callers write only
 * ciphertext or public data through these helpers; temporary names start with {@code .tmp-} and are
 * never mistaken for committed objects.
 */
public final class DurableFiles {
  public static final String TEMP_PREFIX = ".tmp-";
  private static final Set<PosixFilePermission> PRIVATE_DIR =
      PosixFilePermissions.fromString("rwx------");
  private static final Set<PosixFilePermission> PRIVATE_FILE =
      PosixFilePermissions.fromString("rw-------");
  private static final SecureRandom TEMP_NAMES = new SecureRandom();

  private DurableFiles() {}

  /** Creates the directory chain with owner-only permissions where it does not exist. */
  public static Path createPrivateDirectories(Path directory) throws IOException {
    Path absolute = directory.toAbsolutePath();
    Path parent = absolute.getParent();
    if (parent != null && !Files.isDirectory(parent)) {
      createPrivateDirectories(parent);
    }
    if (!Files.isDirectory(absolute)) {
      try {
        Files.createDirectory(absolute, PosixFilePermissions.asFileAttribute(PRIVATE_DIR));
      } catch (FileAlreadyExistsException e) {
        if (!Files.isDirectory(absolute)) {
          throw e;
        }
      }
      if (parent != null) {
        syncDirectory(parent);
      }
    }
    return absolute;
  }

  /** Creates a new owner-only temporary file next to {@code target}. */
  public static Path createTemporarySibling(Path target) throws IOException {
    Path directory = parentOf(target);
    byte[] suffix = new byte[12];
    TEMP_NAMES.nextBytes(suffix);
    Path temp = directory.resolve(TEMP_PREFIX + HexFormat.of().formatHex(suffix));
    Files.createFile(temp, PosixFilePermissions.asFileAttribute(PRIVATE_FILE));
    return temp;
  }

  /** Atomically replaces or creates {@code target} with {@code content}. */
  public static void writeAtomically(Path target, byte[] content) throws IOException {
    Path temp = createTemporarySibling(target);
    try {
      try (FileChannel channel = FileChannel.open(temp, StandardOpenOption.WRITE)) {
        ByteBuffer buffer = ByteBuffer.wrap(content);
        while (buffer.hasRemaining()) {
          channel.write(buffer);
        }
        channel.force(true);
      }
      publish(temp, target, true);
    } finally {
      Files.deleteIfExists(temp);
    }
  }

  /** Atomically creates {@code target}; fails if it already exists. */
  public static void writeNew(Path target, byte[] content) throws IOException {
    Path temp = createTemporarySibling(target);
    try {
      try (FileChannel channel = FileChannel.open(temp, StandardOpenOption.WRITE)) {
        ByteBuffer buffer = ByteBuffer.wrap(content);
        while (buffer.hasRemaining()) {
          channel.write(buffer);
        }
        channel.force(true);
      }
      publish(temp, target, false);
    } finally {
      Files.deleteIfExists(temp);
    }
  }

  /**
   * Publishes an already synced temporary file. With {@code replace == false} an existing target is
   * an error; this uses a hard link so the check and publication are atomic.
   */
  public static void publish(Path temp, Path target, boolean replace) throws IOException {
    if (replace) {
      try {
        Files.move(temp, target, StandardCopyOption.ATOMIC_MOVE);
      } catch (AtomicMoveNotSupportedException e) {
        throw new IOException("filesystem does not support atomic rename", e);
      }
    } else {
      Files.createLink(target, temp);
      Files.delete(temp);
    }
    syncDirectory(parentOf(target));
  }

  public static void syncDirectory(Path directory) throws IOException {
    try (FileChannel channel = FileChannel.open(directory, StandardOpenOption.READ)) {
      channel.force(true);
    }
  }

  /** Deletes a file and syncs its directory so the removal is durable. */
  public static boolean deleteDurably(Path file) throws IOException {
    boolean deleted = Files.deleteIfExists(file);
    if (deleted) {
      syncDirectory(parentOf(file));
    }
    return deleted;
  }

  /** Output stream that forces content to disk when closed. */
  public static OutputStream syncingOutputStream(FileChannel channel) {
    return new SyncingOutputStream(channel);
  }

  private static Path parentOf(Path file) {
    Path parent = file.toAbsolutePath().getParent();
    if (parent == null) {
      throw new IllegalArgumentException("file has no parent directory");
    }
    return parent;
  }

  private static final class SyncingOutputStream extends OutputStream {
    private final FileChannel channel;
    private boolean closed;

    SyncingOutputStream(FileChannel channel) {
      this.channel = channel;
    }

    @Override
    public void write(int b) throws IOException {
      write(new byte[] {(byte) b}, 0, 1);
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
      ByteBuffer buffer = ByteBuffer.wrap(b, off, len);
      while (buffer.hasRemaining()) {
        channel.write(buffer);
      }
    }

    @Override
    public void close() throws IOException {
      if (!closed) {
        closed = true;
        try (channel) {
          channel.force(true);
        }
      }
    }
  }
}
