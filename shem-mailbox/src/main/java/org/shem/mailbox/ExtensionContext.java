package org.shem.mailbox;

import java.io.InputStream;
import java.nio.file.Path;
import java.util.concurrent.Executor;
import org.jspecify.annotations.Nullable;
import org.shem.common.OpaqueId;
import org.shem.crypto.CryptoException;
import org.shem.crypto.Purpose;
import org.shem.crypto.SymmetricKey;
import org.shem.store.StorageException;
import org.shem.store.metadata.MessageRecord;
import org.shem.store.metadata.MetadataStore;

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
