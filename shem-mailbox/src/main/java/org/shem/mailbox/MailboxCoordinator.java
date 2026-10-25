package org.shem.mailbox;

import java.io.IOException;
import java.io.InputStream;
import java.lang.System.Logger.Level;
import java.nio.channels.SeekableByteChannel;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.locks.ReentrantLock;
import org.jspecify.annotations.Nullable;
import org.shem.common.OpaqueId;
import org.shem.crypto.CryptoException;
import org.shem.crypto.Keyring;
import org.shem.crypto.MailboxPrivateKey;
import org.shem.crypto.SymmetricKey;
import org.shem.identity.QuotaLedger;
import org.shem.store.BlobStore;
import org.shem.store.DeliveryTarget;
import org.shem.store.Receipt;
import org.shem.store.ReceiptStore;
import org.shem.store.SpecialUse;
import org.shem.store.StorageException;
import org.shem.store.metadata.Flags;
import org.shem.store.metadata.Folder;
import org.shem.store.metadata.MessageRecord;
import org.shem.store.metadata.MetadataStore;
import org.shem.store.metadata.NewMessage;

/**
 * The single owner of an unlocked mailbox: keyring, master key, metadata writer, and receipt
 * import. Exists only while at least one lease is open; closing the last lease closes the metadata
 * store and wipes Shem's copies of the keys.
 */
public final class MailboxCoordinator {
  private static final System.Logger LOG = System.getLogger(MailboxCoordinator.class.getName());

  private final OpaqueId mailboxId;
  private final MailboxRegistry.Dependencies deps;
  private final java.util.function.Consumer<MailboxCoordinator> onClosed;
  private final MetadataStore metadata;
  private final ReentrantLock keyLock = new ReentrantLock();
  private final ReentrantLock importLock = new ReentrantLock();
  private final Set<MailboxLease> leases = new HashSet<>();
  private final List<ChangeListener> listeners = new CopyOnWriteArrayList<>();
  private Keyring keyring;
  private SymmetricKey masterKey;
  private boolean closed;

  MailboxCoordinator(
      OpaqueId mailboxId,
      MailboxRegistry.Dependencies deps,
      MetadataStore metadata,
      Keyring keyring,
      SymmetricKey masterKey,
      java.util.function.Consumer<MailboxCoordinator> onClosed) {
    this.mailboxId = mailboxId;
    this.deps = deps;
    this.onClosed = onClosed;
    this.metadata = metadata;
    this.keyring = keyring;
    this.masterKey = masterKey;
  }

  public OpaqueId mailboxId() {
    return mailboxId;
  }

  MetadataStore metadata() {
    return metadata;
  }

  // ---- leases ----

  /** Adds a lease unless the coordinator is already closing. */
  synchronized @Nullable MailboxLease tryAddLease(
      Principal principal, @Nullable MailboxLease parent) {
    if (closed) {
      return null;
    }
    MailboxLease lease = new MailboxLease(this, principal, parent);
    leases.add(lease);
    return lease;
  }

  /** Removes a lease; closes the coordinator when it was the last one. */
  void release(MailboxLease lease) {
    boolean last;
    synchronized (this) {
      if (!leases.remove(lease)) {
        return;
      }
      last = leases.isEmpty() && !closed;
      if (last) {
        closed = true;
      }
    }
    if (last) {
      shutdown();
    }
  }

  synchronized List<MailboxLease> leases() {
    return List.copyOf(leases);
  }

  synchronized int leaseCount() {
    return leases.size();
  }

  synchronized boolean isClosed() {
    return closed;
  }

  void revokeWhere(java.util.function.Predicate<Principal> predicate) {
    for (MailboxLease lease : leases()) {
      if (predicate.test(lease.principal())) {
        lease.revoke();
      }
    }
  }

  private void shutdown() {
    importLock.lock();
    keyLock.lock();
    try {
      try {
        metadata.close();
      } catch (StorageException e) {
        LOG.log(Level.WARNING, "metadata close failed: " + e.kind());
      }
      keyring.close();
      masterKey.close();
      listeners.clear();
    } finally {
      keyLock.unlock();
      importLock.unlock();
      onClosed.accept(this);
    }
  }

  AutoCloseable subscribe(ChangeListener listener) {
    listeners.add(listener);
    return () -> listeners.remove(listener);
  }

  void notifyChanged() {
    long txSeq;
    try {
      txSeq = metadata.read(view -> view.txSeq());
    } catch (StorageException e) {
      return;
    }
    for (ChangeListener listener : listeners) {
      listener.changed(txSeq);
    }
  }

  // ---- keys ----

  /** Runs a key-lifecycle change with exclusive access to the keyring and master key. */
  <T extends @Nullable Object> T withKeys(KeyAction<T> action)
      throws StorageException, CryptoException {
    keyLock.lock();
    try {
      checkOpen();
      KeyState state = new KeyState(keyring, masterKey);
      T result = action.run(state);
      if (state.keyring != keyring) {
        keyring.close();
        keyring = state.keyring;
      }
      if (state.masterKey != masterKey) {
        masterKey.close();
        masterKey = state.masterKey;
      }
      return result;
    } finally {
      keyLock.unlock();
    }
  }

  /** Mutable holder handed to key actions; replacing a field transfers ownership. */
  static final class KeyState {
    Keyring keyring;
    SymmetricKey masterKey;

    KeyState(Keyring keyring, SymmetricKey masterKey) {
      this.keyring = keyring;
      this.masterKey = masterKey;
    }
  }

  @FunctionalInterface
  interface KeyAction<T extends @Nullable Object> {
    T run(KeyState state) throws StorageException, CryptoException;
  }

  /** Must be called with the key lock held. */
  private SymmetricKey wrappingKey() throws StorageException {
    int version = metadata.dataVersion();
    SymmetricKey root =
        keyring
            .dataRoot(version)
            .orElseThrow(
                () -> new StorageException(StorageException.Kind.CORRUPT, "data key missing"));
    try {
      return ContentKeys.wrappingKey(root, mailboxId);
    } catch (CryptoException e) {
      throw new StorageException(StorageException.Kind.CORRUPT, "key derivation failed", e);
    }
  }

  SymmetricKey contentKey(MessageRecord record) throws StorageException {
    keyLock.lock();
    try {
      checkOpen();
      try (SymmetricKey wrap = wrappingKey()) {
        return ContentKeys.unwrap(
            wrap, mailboxId, record.blobId(), metadata.dataVersion(), record.wrappedContentKey());
      } catch (CryptoException e) {
        throw new StorageException(StorageException.Kind.CORRUPT, "content key unwrap failed", e);
      }
    } finally {
      keyLock.unlock();
    }
  }

  // ---- message access ----

  InputStream openMessage(MessageRecord record) throws StorageException {
    try (SymmetricKey key = contentKey(record)) {
      return deps.blobs().open(mailboxId, record.blobId(), key);
    }
  }

  SeekableByteChannel openMessageRange(MessageRecord record) throws StorageException {
    try (SymmetricKey key = contentKey(record)) {
      return deps.blobs().openSeekable(mailboxId, record.blobId(), key);
    }
  }

  /** Stores a client-supplied message (IMAP APPEND) with the same durability rules as delivery. */
  long append(OpaqueId folderId, InputStream message, Flags flags, long internalDateMillis)
      throws StorageException {
    long quotaBytes = deps.identity().account(mailboxId).map(a -> a.quotaBytes()).orElse(0L);
    BlobStore.WrittenBlob blob;
    try (QuotaLedger.Reservation reservation =
        deps.quota().reserve(mailboxId, deps.maxMessageBytes() + 8192, quotaBytes)) {
      blob = deps.blobs().write(mailboxId, message, deps.maxMessageBytes());
      reservation.commit(blob.ciphertextBytes());
    } catch (QuotaLedger.QuotaExceeded e) {
      throw new StorageException(StorageException.Kind.LIMIT_EXCEEDED, "quota exceeded", e);
    } catch (IOException e) {
      throw new StorageException(StorageException.Kind.UNAVAILABLE, "quota check failed", e);
    }
    try (SymmetricKey contentKey = blob.contentKey()) {
      long uid =
          commitNewMessage(
              blob.blobId(),
              contentKey,
              blob.plaintextBytes(),
              flags,
              internalDateMillis,
              m -> metadata.write(tx -> tx.append(folderId, m)));
      notifyChanged();
      return uid;
    }
  }

  /** Commits a new message whose content key is wrapped under the current data version. */
  @FunctionalInterface
  private interface MessageCommit<T extends @Nullable Object> {
    T commit(NewMessage message) throws StorageException;
  }

  /**
   * Computes the summary from the stored blob, then wraps the content key and commits while holding
   * the key lock, so a concurrent re-encryption cannot change the data version in between.
   */
  private <T extends @Nullable Object> T commitNewMessage(
      OpaqueId blobId,
      SymmetricKey contentKey,
      long size,
      Flags flags,
      long internalDateMillis,
      MessageCommit<T> commit)
      throws StorageException {
    MessageSummary summary;
    try (InputStream in = deps.blobs().open(mailboxId, blobId, contentKey)) {
      summary = MessageSummary.compute(in);
    } catch (IOException e) {
      throw new StorageException(StorageException.Kind.CORRUPT, "stored message unreadable", e);
    }
    keyLock.lock();
    try {
      checkOpen();
      NewMessage message;
      try (SymmetricKey wrap = wrappingKey()) {
        message =
            new NewMessage(
                blobId,
                ContentKeys.wrap(wrap, mailboxId, blobId, metadata.dataVersion(), contentKey),
                size,
                internalDateMillis,
                flags,
                summary.encode());
      } catch (CryptoException e) {
        throw new StorageException(StorageException.Kind.UNAVAILABLE, "content key wrap failed", e);
      }
      return commit.commit(message);
    } finally {
      keyLock.unlock();
    }
  }

  // ---- receipt import ----

  /**
   * Imports up to {@code max} pending receipts in stable order. Each import commits the message,
   * its folder resolution, and the delivery-id checkpoint in one transaction before the receipt
   * file is retired, so replay after a crash is idempotent.
   *
   * @return number of receipts processed
   */
  int importPending(int max) throws StorageException {
    importLock.lock();
    try {
      checkOpen();
      int processed = 0;
      for (ReceiptStore.PendingReceipt pending : deps.receipts().list(mailboxId)) {
        if (processed >= max) {
          break;
        }
        importOne(pending);
        processed++;
      }
      if (processed > 0) {
        notifyChanged();
      }
      return processed;
    } finally {
      importLock.unlock();
    }
  }

  private void importOne(ReceiptStore.PendingReceipt pending) throws StorageException {
    try (Receipt receipt = openReceipt(pending)) {
      if (metadata.read(view -> view.receiptImported(receipt.deliveryId()))) {
        deps.receipts().retire(pending);
        return;
      }
      if (!deps.blobs().exists(mailboxId, receipt.blobId())) {
        throw new StorageException(
            StorageException.Kind.CORRUPT, "receipt references missing blob");
      }
      Flags flags;
      try {
        flags = new Flags(receipt.systemFlags() & Flags.ALL_SYSTEM, receipt.keywords());
      } catch (IllegalArgumentException e) {
        flags = new Flags(receipt.systemFlags() & Flags.ALL_SYSTEM, List.of());
      }
      DeliveryTarget target = receipt.target();
      commitNewMessage(
          receipt.blobId(),
          receipt.contentKey(),
          receipt.plaintextBytes(),
          flags,
          receipt.internalDateMillis(),
          message ->
              metadata.write(
                  tx -> {
                    Folder folder = resolveTarget(tx, target);
                    tx.append(folder.folderId(), message);
                    tx.markReceiptImported(receipt.deliveryId());
                    return null;
                  }));
    }
    deps.receipts().retire(pending);
  }

  private Receipt openReceipt(ReceiptStore.PendingReceipt pending) throws StorageException {
    keyLock.lock();
    try {
      checkOpen();
      Keyring current = keyring;
      return deps.receipts().open(mailboxId, pending, current::privateKey);
    } finally {
      keyLock.unlock();
    }
  }

  static Folder resolveTarget(org.shem.store.metadata.Tx tx, DeliveryTarget target)
      throws StorageException {
    if (target instanceof DeliveryTarget.Folder f) {
      Optional<Folder> folder = tx.folder(f.folderId());
      if (folder.isPresent()) {
        return folder.get();
      }
    }
    SpecialUse role = target instanceof DeliveryTarget.Role r ? r.role() : SpecialUse.INBOX;
    Optional<Folder> existing = tx.folderByRole(role);
    if (existing.isPresent()) {
      return existing.get();
    }
    String name = MailboxProvisioning.defaultName(role);
    Optional<Folder> byName = tx.folderByName(name);
    return byName.isPresent() ? byName.get() : tx.createFolder(name, role);
  }

  /** Private keys still needed for pending receipts (by key version). */
  Set<Integer> keyVersionsOfPendingReceipts() throws StorageException {
    Set<Integer> versions = new HashSet<>();
    for (ReceiptStore.PendingReceipt pending : deps.receipts().list(mailboxId)) {
      versions.add(deps.receipts().keyVersion(pending));
    }
    return versions;
  }

  // ---- garbage collection ----

  /**
   * Deletes blobs that no message and no pending receipt references and that are older than {@code
   * grace}. Returns freed ciphertext bytes.
   */
  long collectGarbage(Duration grace, Clock clock) throws StorageException {
    importLock.lock();
    try {
      checkOpen();
      Set<OpaqueId> live = new HashSet<>(metadata.referencedBlobs());
      for (ReceiptStore.PendingReceipt pending : deps.receipts().list(mailboxId)) {
        try (Receipt receipt = openReceipt(pending)) {
          live.add(receipt.blobId());
        }
      }
      long freed = 0;
      long cutoff = clock.millis() - grace.toMillis();
      List<OpaqueId> candidates = new ArrayList<>(deps.blobs().list(mailboxId));
      for (OpaqueId blobId : candidates) {
        if (!live.contains(blobId) && deps.blobs().lastModifiedMillis(mailboxId, blobId) < cutoff) {
          long size = deps.blobs().delete(mailboxId, blobId);
          deps.quota().released(mailboxId, size);
          freed += size;
        }
      }
      deps.blobs().sweepTemporaryFiles(mailboxId);
      return freed;
    } finally {
      importLock.unlock();
    }
  }

  // ---- re-encryption support ----

  /**
   * Re-encrypts metadata under {@code newRoot}, rewrapping every content key. Caller holds the key
   * lock through {@link #withKeys} and has already made {@code newRoot} durable in the keyring.
   */
  void reencryptMetadata(KeyState state, int newVersion) throws StorageException, CryptoException {
    int oldVersion = metadata.dataVersion();
    SymmetricKey oldRoot =
        state
            .keyring
            .dataRoot(oldVersion)
            .orElseThrow(
                () -> new StorageException(StorageException.Kind.CORRUPT, "data key missing"));
    SymmetricKey newRoot =
        state
            .keyring
            .dataRoot(newVersion)
            .orElseThrow(
                () -> new StorageException(StorageException.Kind.CORRUPT, "data key missing"));
    try (SymmetricKey oldWrap = ContentKeys.wrappingKey(oldRoot, mailboxId);
        SymmetricKey newWrap = ContentKeys.wrappingKey(newRoot, mailboxId)) {
      metadata.reencrypt(
          newRoot,
          newVersion,
          record -> {
            try (SymmetricKey key =
                ContentKeys.unwrap(
                    oldWrap, mailboxId, record.blobId(), oldVersion, record.wrappedContentKey())) {
              return new MessageRecord(
                  record.blobId(),
                  ContentKeys.wrap(newWrap, mailboxId, record.blobId(), newVersion, key),
                  record.size(),
                  record.internalDateMillis(),
                  record.modSeq(),
                  record.flags(),
                  record.summary());
            } catch (CryptoException e) {
              throw new StorageException(
                  StorageException.Kind.CORRUPT, "content key rewrap failed", e);
            }
          });
    }
  }

  Optional<MailboxPrivateKey> privateKey(int version) {
    return keyring.privateKey(version);
  }

  private void checkOpen() throws StorageException {
    if (isClosed()) {
      throw new StorageException(StorageException.Kind.UNAVAILABLE, "mailbox closed");
    }
  }
}
