package org.shem.mailbox;

import java.io.InputStream;
import java.nio.channels.SeekableByteChannel;
import java.util.ArrayList;
import java.util.List;
import org.jspecify.annotations.Nullable;
import org.shem.common.OpaqueId;
import org.shem.store.StorageException;
import org.shem.store.metadata.Flags;
import org.shem.store.metadata.MessageRecord;
import org.shem.store.metadata.MetadataStore;

/**
 * A closeable capability to an unlocked mailbox, bound to one principal and its originating slot.
 * Protocol adapters hold one per session; background work uses {@link #child()} leases. Every
 * operation checks the lease first, so revocation takes effect at the next call.
 */
public final class MailboxLease implements AutoCloseable {
  private final MailboxCoordinator coordinator;
  private final Principal principal;
  private final @Nullable MailboxLease parent;
  private final List<MailboxLease> children = new ArrayList<>();
  private final List<Runnable> revocationHooks = new ArrayList<>();
  private volatile boolean revoked;
  private boolean released;

  MailboxLease(MailboxCoordinator coordinator, Principal principal, @Nullable MailboxLease parent) {
    this.coordinator = coordinator;
    this.principal = principal;
    this.parent = parent;
  }

  public Principal principal() {
    return principal;
  }

  public OpaqueId mailboxId() {
    return principal.mailboxId();
  }

  public boolean isValid() {
    return !revoked && (parent == null || parent.isValid());
  }

  public <T extends @Nullable Object> T read(MetadataStore.ReadBody<T> body)
      throws StorageException {
    require(Capability.MAIL_ACCESS);
    return coordinator.metadata().read(body);
  }

  public <T extends @Nullable Object> T write(MetadataStore.TxBody<T> body)
      throws StorageException {
    require(Capability.MAIL_ACCESS);
    T result = coordinator.metadata().write(body);
    coordinator.notifyChanged();
    return result;
  }

  /** Verified plaintext stream of a stored message. */
  public InputStream openMessage(MessageRecord record) throws StorageException {
    require(Capability.MAIL_ACCESS);
    return coordinator.openMessage(record);
  }

  public SeekableByteChannel openMessageRange(MessageRecord record) throws StorageException {
    require(Capability.MAIL_ACCESS);
    return coordinator.openMessageRange(record);
  }

  /** IMAP APPEND: encrypt, store durably, and add to a folder; returns the new UID. */
  public long append(OpaqueId folderId, InputStream message, Flags flags, long internalDateMillis)
      throws StorageException {
    require(Capability.MAIL_ACCESS);
    return coordinator.append(folderId, message, flags, internalDateMillis);
  }

  /** Imports pending deliveries; returns how many were processed. */
  public int importPending(int max) throws StorageException {
    checkValid();
    return coordinator.importPending(max);
  }

  /** Registers for change notifications until the returned handle is closed. */
  public AutoCloseable subscribe(ChangeListener listener) {
    checkValid();
    return coordinator.subscribe(listener);
  }

  /** Runs {@code hook} when this lease is revoked (not on ordinary close). */
  public synchronized void onRevoked(Runnable hook) {
    revocationHooks.add(hook);
  }

  /**
   * A child lease for bounded background work. It is revoked with its parent and keeps the mailbox
   * unlocked only while open.
   */
  public MailboxLease child() {
    checkValid();
    MailboxLease child = coordinator.tryAddLease(principal, this);
    if (child == null) {
      throw new RevokedLeaseException();
    }
    synchronized (this) {
      children.add(child);
    }
    return child;
  }

  MailboxCoordinator coordinator() {
    checkValid();
    return coordinator;
  }

  void require(Capability capability) {
    checkValid();
    if (!principal.can(capability)) {
      throw new SecurityException("capability not granted");
    }
  }

  void checkValid() {
    if (!isValid()) {
      throw new RevokedLeaseException();
    }
  }

  /** Revokes this lease and its children, then releases them. */
  void revoke() {
    List<Runnable> hooks;
    List<MailboxLease> kids;
    synchronized (this) {
      if (revoked) {
        return;
      }
      revoked = true;
      hooks = List.copyOf(revocationHooks);
      kids = List.copyOf(children);
    }
    kids.forEach(MailboxLease::revoke);
    for (Runnable hook : hooks) {
      hook.run();
    }
    close();
  }

  @Override
  public void close() {
    List<MailboxLease> kids;
    synchronized (this) {
      if (released) {
        return;
      }
      released = true;
      revoked = true;
      kids = List.copyOf(children);
    }
    kids.forEach(MailboxLease::close);
    coordinator.release(this);
  }

  @Override
  public String toString() {
    return "MailboxLease[" + principal.slotKind() + "]";
  }
}
