package org.shem.app;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;
import org.shem.common.DurableFiles;

/**
 * The server's data directory and its exclusive process lock. Layout: {@code routing/} (public
 * routing directory), {@code mailboxes/} (ciphertext only), {@code spool/} (ciphertext-only
 * provisional files), {@code queue/} (outbound plaintext queue, the documented exception), and
 * {@code dkim/} (server-wide DKIM signing keys).
 */
public final class DataDirectory implements AutoCloseable {
  private final Path root;
  private final FileChannel lockChannel;
  private final FileLock lock;

  private DataDirectory(Path root, FileChannel lockChannel, FileLock lock) {
    this.root = root;
    this.lockChannel = lockChannel;
    this.lock = lock;
  }

  /** Creates or validates the directory and takes the exclusive lock (fails if already held). */
  public static DataDirectory open(Path root) throws IOException {
    Path absolute = DurableFiles.createPrivateDirectories(root);
    Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(absolute);
    if (permissions.contains(PosixFilePermission.GROUP_READ)
        || permissions.contains(PosixFilePermission.OTHERS_READ)
        || permissions.contains(PosixFilePermission.GROUP_WRITE)
        || permissions.contains(PosixFilePermission.OTHERS_WRITE)) {
      throw new IOException("data directory must be accessible by its owner only");
    }
    FileChannel channel =
        FileChannel.open(
            absolute.resolve("shem.lock"), StandardOpenOption.CREATE, StandardOpenOption.WRITE);
    FileLock lock;
    try {
      lock = channel.tryLock();
    } catch (java.nio.channels.OverlappingFileLockException e) {
      lock = null;
    }
    if (lock == null) {
      channel.close();
      throw new IOException("data directory is in use by another Shem process");
    }
    for (String sub : new String[] {"routing", "mailboxes", "spool", "queue", "dkim"}) {
      DurableFiles.createPrivateDirectories(absolute.resolve(sub));
    }
    return new DataDirectory(absolute, channel, lock);
  }

  public Path root() {
    return root;
  }

  public Path routingFile() {
    return root.resolve("routing/directory.bin");
  }

  public Path mailboxes() {
    return root.resolve("mailboxes");
  }

  public Path spool() {
    return root.resolve("spool");
  }

  public Path queue() {
    return root.resolve("queue");
  }

  public Path dkimKeys() {
    return root.resolve("dkim");
  }

  @Override
  public void close() throws IOException {
    try {
      lock.release();
    } finally {
      lockChannel.close();
    }
  }
}
