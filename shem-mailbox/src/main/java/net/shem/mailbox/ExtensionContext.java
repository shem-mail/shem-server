package net.shem.mailbox;

import java.io.InputStream;
import java.nio.file.Path;
import java.util.concurrent.Executor;
import net.shem.common.OpaqueId;
import net.shem.crypto.CryptoException;
import net.shem.crypto.Purpose;
import net.shem.crypto.SymmetricKey;
import net.shem.store.StorageException;
import net.shem.store.metadata.MessageRecord;
import net.shem.store.metadata.MetadataStore;
import org.jspecify.annotations.Nullable;

/**
 * Narrow access an extension gets to its unlocked mailbox: metadata reads, verified message
 * content, change notifications, a private directory, a purpose-bound key, and a bounded executor.
 * No private keys, slots, or write access to mailbox metadata.
 */
public final class ExtensionContext {
  private final MailboxCoordinator coordinator;
  private final Path directory;
  private final Executor executor;
  private final int dataVersion;

  ExtensionContext(
      MailboxCoordinator coordinator, Path directory, Executor executor, int dataVersion) {
    this.coordinator = coordinator;
    this.directory = directory;
    this.executor = executor;
    this.dataVersion = dataVersion;
  }

  public OpaqueId mailboxId() {
    return coordinator.mailboxId();
  }

  /** Directory reserved for this extension (created on demand by the extension). */
  public Path directory() {
    return directory;
  }

  /** Data-key version the extension's key belongs to; a change means rebuild. */
  public int dataVersion() {
    return dataVersion;
  }

  /**
   * A key for {@code purpose}, derived from the current data root and the mailbox id. The caller
   * owns and must close it.
   */
  public SymmetricKey deriveKey(Purpose purpose) throws StorageException, CryptoException {
    return coordinator.deriveExtensionKey(purpose, dataVersion);
  }

  public <T extends @Nullable Object> T read(MetadataStore.ReadBody<T> body)
      throws StorageException {
    return coordinator.metadata().read(body);
  }

  public InputStream openMessage(MessageRecord record) throws StorageException {
    return coordinator.openMessage(record);
  }

  public AutoCloseable subscribe(ChangeListener listener) {
    return coordinator.subscribe(listener);
  }

  /** True until the mailbox locks; long-running work must stop when this turns false. */
  public boolean isOpen() {
    return !coordinator.isClosed();
  }

  public Executor executor() {
    return executor;
  }
}
