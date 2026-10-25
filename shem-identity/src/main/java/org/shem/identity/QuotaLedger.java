package org.shem.identity;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.HashMap;
import java.util.Map;
import org.shem.common.OpaqueId;

/**
 * Physical-byte quota admission while mailboxes are locked.
 *
 * <p>Usage is the ciphertext size already visible on disk, measured by scanning the mailbox
 * directory once per process lifetime; no per-message plaintext ledger is persisted. Concurrent
 * deliveries reserve conservatively before writing, and each reservation is released or committed
 * exactly once.
 */
public final class QuotaLedger {
  /** Locates the on-disk directory of a mailbox. */
  @FunctionalInterface
  public interface MailboxLocator {
    Path directoryOf(OpaqueId mailboxId);
  }

  private final MailboxLocator locator;
  private final Map<OpaqueId, Usage> usage = new HashMap<>();

  public QuotaLedger(MailboxLocator locator) {
    this.locator = locator;
  }

  /** Thrown when admitting the reservation would exceed the quota. */
  public static final class QuotaExceeded extends Exception {
    private static final long serialVersionUID = 1L;

    public QuotaExceeded() {
      super("mailbox quota exceeded");
    }
  }

  /** A pending reservation; must be committed or closed (released). */
  public final class Reservation implements AutoCloseable {
    private final OpaqueId mailboxId;
    private final long bytes;
    private boolean settled;

    private Reservation(OpaqueId mailboxId, long bytes) {
      this.mailboxId = mailboxId;
      this.bytes = bytes;
    }

    /** Converts the reservation into committed usage of {@code actualBytes}. */
    public void commit(long actualBytes) {
      synchronized (QuotaLedger.this) {
        if (settled) {
          throw new IllegalStateException("reservation already settled");
        }
        settled = true;
        Usage u = usage.get(mailboxId);
        if (u != null) {
          u.reserved -= bytes;
          u.used += actualBytes;
        }
      }
    }

    @Override
    public void close() {
      synchronized (QuotaLedger.this) {
        if (!settled) {
          settled = true;
          Usage u = usage.get(mailboxId);
          if (u != null) {
            u.reserved -= bytes;
          }
        }
      }
    }
  }

  public synchronized Reservation reserve(OpaqueId mailboxId, long bytes, long quotaBytes)
      throws QuotaExceeded, IOException {
    if (bytes < 0) {
      throw new IllegalArgumentException("negative reservation");
    }
    Usage u = load(mailboxId);
    if (quotaBytes > 0 && u.used + u.reserved + bytes > quotaBytes) {
      throw new QuotaExceeded();
    }
    u.reserved += bytes;
    return new Reservation(mailboxId, bytes);
  }

  /** Records bytes freed by garbage collection or expunge. */
  public synchronized void released(OpaqueId mailboxId, long bytes) {
    Usage u = usage.get(mailboxId);
    if (u != null) {
      u.used = Math.max(0, u.used - bytes);
    }
  }

  public synchronized long usedBytes(OpaqueId mailboxId) throws IOException {
    return load(mailboxId).used;
  }

  public synchronized void forget(OpaqueId mailboxId) {
    usage.remove(mailboxId);
  }

  private Usage load(OpaqueId mailboxId) throws IOException {
    Usage u = usage.get(mailboxId);
    if (u == null) {
      u = new Usage();
      u.used = sizeOf(locator.directoryOf(mailboxId));
      usage.put(mailboxId, u);
    }
    return u;
  }

  private static long sizeOf(Path directory) throws IOException {
    if (!Files.isDirectory(directory)) {
      return 0;
    }
    long[] total = new long[1];
    Files.walkFileTree(
        directory,
        new SimpleFileVisitor<>() {
          @Override
          public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
            total[0] += attrs.size();
            return FileVisitResult.CONTINUE;
          }
        });
    return total[0];
  }

  private static final class Usage {
    long used;
    long reserved;
  }
}
