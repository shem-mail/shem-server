package org.shem.mailbox;

import java.lang.System.Logger.Level;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import org.shem.common.OpaqueId;
import org.shem.crypto.Keyring;
import org.shem.crypto.SymmetricKey;
import org.shem.delivery.DeliveryListener;
import org.shem.identity.AccountState;
import org.shem.identity.IdentityService;
import org.shem.identity.QuotaLedger;
import org.shem.store.BlobStore;
import org.shem.store.MailboxPaths;
import org.shem.store.ReceiptStore;
import org.shem.store.StorageException;
import org.shem.store.metadata.MetadataStore;

/**
 * Process-wide registry guaranteeing at most one {@link MailboxCoordinator} (and therefore one
 * metadata writer) per mailbox. Also receives delivery notifications and schedules bounded imports
 * for unlocked mailboxes.
 */
public final class MailboxRegistry implements DeliveryListener, AutoCloseable {
  private static final System.Logger LOG = System.getLogger(MailboxRegistry.class.getName());
  static final int SYNCHRONOUS_IMPORT_LIMIT = 500;
  private static final java.time.Duration SHUTDOWN_WAIT = java.time.Duration.ofSeconds(30);
  static final int BACKGROUND_IMPORT_BATCH = 200;

  /** Collaborators shared by all coordinators. */
  public record Dependencies(
      MailboxPaths paths,
      BlobStore blobs,
      ReceiptStore receipts,
      QuotaLedger quota,
      IdentityService identity,
      MetadataStore.Environment metadataEnvironment,
      long maxMessageBytes,
      List<MailboxExtensionFactory> extensions,
      java.util.concurrent.Executor extensionExecutor) {
    public Dependencies {
      extensions = List.copyOf(extensions);
    }

    /** Dependencies without extensions (tests, tools). */
    public Dependencies(
        MailboxPaths paths,
        BlobStore blobs,
        ReceiptStore receipts,
        QuotaLedger quota,
        IdentityService identity,
        MetadataStore.Environment metadataEnvironment,
        long maxMessageBytes) {
      this(
          paths,
          blobs,
          receipts,
          quota,
          identity,
          metadataEnvironment,
          maxMessageBytes,
          List.of(),
          Runnable::run);
    }
  }

  private final Dependencies deps;
  private final ExecutorService background;
  private final ConcurrentHashMap<OpaqueId, MailboxCoordinator> active = new ConcurrentHashMap<>();
  private final ConcurrentHashMap<OpaqueId, Object> locks = new ConcurrentHashMap<>();

  public MailboxRegistry(Dependencies deps, ExecutorService background) {
    this.deps = deps;
    this.background = background;
    deps.identity()
        .subscribe(
            (before, after) -> {
              if (!after.state().allowsAuthentication() || after.state() == AccountState.DELETED) {
                revokeMailbox(after.mailboxId());
              }
            });
  }

  Dependencies dependencies() {
    return deps;
  }

  /**
   * Returns a lease on the mailbox, creating the coordinator from {@code keyring} and {@code
   * masterKey} if none is active. Takes ownership of both keys in every case.
   */
  MailboxLease attach(Principal principal, Keyring keyring, SymmetricKey masterKey)
      throws StorageException {
    OpaqueId mailboxId = principal.mailboxId();
    Object lock = locks.computeIfAbsent(mailboxId, id -> new Object());
    synchronized (lock) {
      MailboxCoordinator existing = active.get(mailboxId);
      if (existing != null) {
        MailboxLease lease = existing.tryAddLease(principal, null);
        if (lease != null) {
          keyring.close();
          masterKey.close();
          return lease;
        }
        // The last session is closing on another thread; its metadata store is still open.
        awaitShutdown(existing, keyring, masterKey);
      }
      MetadataStore metadata;
      try {
        metadata =
            MetadataStore.open(
                deps.paths().metadata(mailboxId),
                mailboxId,
                keyring::dataRoot,
                deps.metadataEnvironment());
      } catch (StorageException e) {
        keyring.close();
        masterKey.close();
        throw e;
      }
      MailboxCoordinator coordinator =
          new MailboxCoordinator(mailboxId, deps, metadata, keyring, masterKey, this::closed);
      MailboxLease lease = coordinator.tryAddLease(principal, null);
      if (lease == null) {
        throw new IllegalStateException("new coordinator refused lease");
      }
      active.put(mailboxId, coordinator);
      coordinator.openExtensions();
      try {
        int imported = coordinator.importPending(SYNCHRONOUS_IMPORT_LIMIT);
        if (imported == SYNCHRONOUS_IMPORT_LIMIT) {
          delivered(mailboxId);
        }
      } catch (StorageException e) {
        lease.close();
        throw e;
      }
      return lease;
    }
  }

  private static void awaitShutdown(
      MailboxCoordinator closing, Keyring keyring, SymmetricKey masterKey) throws StorageException {
    boolean done;
    try {
      done = closing.awaitTerminated(SHUTDOWN_WAIT);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      done = false;
    }
    if (!done) {
      keyring.close();
      masterKey.close();
      throw new StorageException(StorageException.Kind.UNAVAILABLE, "mailbox is still closing");
    }
  }

  public Optional<MailboxCoordinator> coordinator(OpaqueId mailboxId) {
    return Optional.ofNullable(active.get(mailboxId));
  }

  public boolean isUnlocked(OpaqueId mailboxId) {
    MailboxCoordinator coordinator = active.get(mailboxId);
    return coordinator != null && !coordinator.isClosed();
  }

  /** Delivery notification: import in the background with a child lease, if unlocked. */
  @Override
  public void delivered(OpaqueId mailboxId) {
    MailboxCoordinator coordinator = active.get(mailboxId);
    if (coordinator == null || coordinator.isClosed()) {
      return;
    }
    try {
      background.execute(() -> importInBackground(coordinator));
    } catch (RejectedExecutionException e) {
      LOG.log(Level.DEBUG, "background import queue full; import deferred to next session event");
    }
  }

  private void importInBackground(MailboxCoordinator coordinator) {
    MailboxLease anchor = coordinator.leases().stream().findFirst().orElse(null);
    if (anchor == null) {
      return;
    }
    try (MailboxLease child = anchor.child()) {
      int processed;
      do {
        processed = child.importPending(BACKGROUND_IMPORT_BATCH);
      } while (processed == BACKGROUND_IMPORT_BATCH && child.isValid());
    } catch (RevokedLeaseException e) {
      // The session ended; pending receipts stay durable for the next unlock.
    } catch (StorageException e) {
      LOG.log(Level.WARNING, "background import failed: " + e.kind());
    }
  }

  /** Revokes every lease of a mailbox (account blocked, deleted, or key rotation policy). */
  public void revokeMailbox(OpaqueId mailboxId) {
    MailboxCoordinator coordinator = active.get(mailboxId);
    if (coordinator != null) {
      coordinator.revokeWhere(p -> true);
    }
  }

  /** Revokes the leases that were unlocked through {@code slotId}. */
  public void revokeSlot(OpaqueId mailboxId, OpaqueId slotId) {
    MailboxCoordinator coordinator = active.get(mailboxId);
    if (coordinator != null) {
      coordinator.revokeWhere(p -> p.slotId().equals(slotId));
    }
  }

  private void closed(MailboxCoordinator coordinator) {
    active.remove(coordinator.mailboxId(), coordinator);
  }

  /** Revokes all sessions, closing every coordinator (shutdown path). */
  @Override
  public void close() {
    for (MailboxCoordinator coordinator : active.values()) {
      coordinator.revokeWhere(p -> true);
    }
  }
}
