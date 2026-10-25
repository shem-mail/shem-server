package org.shem.delivery;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import org.shem.common.DurableFiles;
import org.shem.crypto.AssociatedData;
import org.shem.crypto.CryptoException;
import org.shem.crypto.CryptoProfile;
import org.shem.crypto.Purpose;
import org.shem.crypto.StreamingCipher;
import org.shem.crypto.SymmetricKey;

/**
 * Provisional storage for an incoming message that is too large to buffer in memory. The file is
 * encrypted under an ephemeral key that exists only in this object; after a crash or {@link
 * #close()} the file is unreadable ciphertext and is deleted. This is not delivery acceptance.
 */
public final class EncryptedSpool implements MessageSource, AutoCloseable {
  private final Path file;
  private final SymmetricKey key;
  private final AssociatedData context;
  private long size;
  private boolean sealed;

  private EncryptedSpool(Path file, SymmetricKey key, AssociatedData context) {
    this.file = file;
    this.key = key;
    this.context = context;
  }

  /** Creates a spool in {@code directory}, which must be a private ciphertext-only directory. */
  public static EncryptedSpool create(Path directory, SecureRandom random) throws IOException {
    DurableFiles.createPrivateDirectories(directory);
    Path file = DurableFiles.createTemporarySibling(directory.resolve("spool"));
    return new EncryptedSpool(
        file,
        SymmetricKey.generate(random),
        AssociatedData.builder(Purpose.MESSAGE_BLOB, 1).text("use", "provisional-spool").build());
  }

  /** Streams the message into the spool, enforcing {@code maxBytes}. */
  public void fill(InputStream message, long maxBytes) throws IOException, SpoolLimitException {
    if (sealed) {
      throw new IllegalStateException("spool already filled");
    }
    try (FileChannel channel = FileChannel.open(file, StandardOpenOption.WRITE);
        OutputStream out =
            cipher().encrypt(java.nio.channels.Channels.newOutputStream(channel), context)) {
      byte[] buffer = new byte[16 * 1024];
      int n;
      while ((n = message.read(buffer)) > 0) {
        size += n;
        if (size > maxBytes) {
          throw new SpoolLimitException();
        }
        out.write(buffer, 0, n);
      }
    } catch (CryptoException e) {
      throw new IOException("spool encryption failed", e);
    }
    sealed = true;
  }

  @Override
  public InputStream open() throws IOException {
    if (!sealed) {
      throw new IllegalStateException("spool not filled");
    }
    try {
      return cipher().decrypt(Files.newInputStream(file), context);
    } catch (CryptoException e) {
      throw new IOException("spool decryption failed", e);
    }
  }

  @Override
  public long size() {
    return size;
  }

  private StreamingCipher cipher() throws CryptoException {
    return key.streaming(CryptoProfile.BLOB_SEGMENT_BYTES);
  }

  @Override
  public void close() throws IOException {
    key.close();
    Files.deleteIfExists(file);
  }

  /** The message exceeded the configured size limit. */
  public static final class SpoolLimitException extends Exception {
    private static final long serialVersionUID = 1L;

    public SpoolLimitException() {
      super("message exceeds size limit");
    }
  }
}
