package org.shem.smtp;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import org.apache.james.core.MailAddress;
import org.apache.james.core.MaybeSender;
import org.apache.james.protocols.smtp.MailEnvelope;
import org.jspecify.annotations.Nullable;
import org.shem.delivery.EncryptedSpool;
import org.shem.delivery.MessageSource;

/**
 * DATA buffer for one transaction: in memory up to a threshold, then an {@link EncryptedSpool}
 * whose key exists only in this object. Never writes plaintext to disk. {@link #close()} wipes the
 * memory buffer and deletes the spool; it is idempotent.
 */
final class SpoolingEnvelope implements MailEnvelope, MessageSource, AutoCloseable {
  private final MaybeSender sender;
  private final List<MailAddress> recipients;
  private final long maxBytes;
  private final int memoryThreshold;
  private final Path spoolDirectory;
  private final SecureRandom random;
  private byte[] memory = new byte[0];
  private int memoryLength;
  private @Nullable EncryptedSpool spool;
  private @Nullable OutputStream spoolOut;
  private long size;
  private boolean sealed;
  private boolean closed;
  private final OutputStream output = new Output();

  SpoolingEnvelope(
      MaybeSender sender,
      List<MailAddress> recipients,
      long maxBytes,
      int memoryThreshold,
      Path spoolDirectory,
      SecureRandom random) {
    this.sender = sender;
    this.recipients = List.copyOf(recipients);
    this.maxBytes = maxBytes;
    this.memoryThreshold = memoryThreshold;
    this.spoolDirectory = spoolDirectory;
    this.random = random;
  }

  @Override
  public MaybeSender getMaybeSender() {
    return sender;
  }

  @Override
  public List<MailAddress> getRecipients() {
    return recipients;
  }

  @Override
  public long getSize() {
    return size;
  }

  @Override
  public OutputStream getMessageOutputStream() {
    return output;
  }

  @Override
  public InputStream getMessageInputStream() throws IOException {
    return open();
  }

  /** Whether DATA completed and the content can be read. */
  synchronized boolean sealed() {
    return sealed && !closed;
  }

  /** Whether the content went to an encrypted provisional file. */
  synchronized boolean spooled() {
    return spool != null;
  }

  @Override
  public synchronized InputStream open() throws IOException {
    if (!sealed()) {
      throw new IllegalStateException("message not complete");
    }
    EncryptedSpool current = spool;
    return current != null ? current.open() : new ByteArrayInputStream(memory, 0, memoryLength);
  }

  @Override
  public synchronized long size() {
    return size;
  }

  @Override
  public synchronized void close() throws IOException {
    if (closed) {
      return;
    }
    closed = true;
    Arrays.fill(memory, (byte) 0);
    memory = new byte[0];
    memoryLength = 0;
    EncryptedSpool current = spool;
    spool = null;
    if (current != null) {
      try {
        OutputStream out = spoolOut;
        if (out != null && !sealed) {
          out.close();
        }
      } finally {
        current.close();
      }
    }
  }

  private synchronized void write(byte[] bytes, int offset, int length) throws IOException {
    if (closed || sealed) {
      throw new IOException("envelope is closed");
    }
    if (size + length > maxBytes) {
      throw new IOException("message exceeds size limit");
    }
    OutputStream out = spoolOut;
    if (out == null && memoryLength + length > memoryThreshold) {
      out = startSpool();
    }
    if (out != null) {
      out.write(bytes, offset, length);
    } else {
      if (memoryLength + length > memory.length) {
        int capacity =
            Math.max(
                memoryLength + length,
                Math.min(memoryThreshold, Math.max(8192, memory.length * 2)));
        byte[] grown = Arrays.copyOf(memory, capacity);
        Arrays.fill(memory, (byte) 0);
        memory = grown;
      }
      System.arraycopy(bytes, offset, memory, memoryLength, length);
      memoryLength += length;
    }
    size += length;
  }

  private OutputStream startSpool() throws IOException {
    EncryptedSpool created = EncryptedSpool.create(spoolDirectory, random);
    spool = created;
    OutputStream out = created.output(maxBytes);
    spoolOut = out;
    out.write(memory, 0, memoryLength);
    Arrays.fill(memory, (byte) 0);
    memory = new byte[0];
    memoryLength = 0;
    return out;
  }

  private synchronized void seal() throws IOException {
    if (closed || sealed) {
      return;
    }
    OutputStream out = spoolOut;
    if (out != null) {
      out.close();
    }
    sealed = true;
  }

  /** The stream James writes DATA lines to; closing it marks DATA complete. */
  private final class Output extends OutputStream {
    @Override
    public void write(int b) throws IOException {
      write(new byte[] {(byte) b}, 0, 1);
    }

    @Override
    public void write(byte[] bytes, int offset, int length) throws IOException {
      SpoolingEnvelope.this.write(bytes, offset, length);
    }

    @Override
    public void flush() {
      // James flushes after every line; segments are written when full, so nothing to do here.
    }

    @Override
    public void close() throws IOException {
      seal();
    }
  }
}
