package org.shem.store.metadata;

import java.util.Collection;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.shem.common.ImmutableBytes;
import org.shem.common.OpaqueId;
import org.shem.store.SpecialUse;
import org.shem.store.StorageException;

/** Consistent read access to one mailbox's metadata at a single commit point. */
public interface ReadView {
  /** Commit sequence of this view; increases with every committed transaction. */
  long txSeq();

  long highestModSeq();

  Collection<Folder> folders();

  Optional<Folder> folder(OpaqueId folderId);

  Optional<Folder> folderByName(String name);

  Optional<Folder> folderByRole(SpecialUse role);

  Set<String> subscriptions();

  Optional<MessageRecord> message(MessageKey key) throws StorageException;

  /** Sorted UIDs of a folder. */
  long[] uids(OpaqueId folderId) throws StorageException;

  /** Visits messages of a folder in UID order; stop early by returning {@code false}. */
  void forEachMessage(OpaqueId folderId, MessageVisitor visitor) throws StorageException;

  boolean receiptImported(OpaqueId receiptId);

  Map<OpaqueId, Long> importedReceipts();

  Optional<ImmutableBytes> property(String key);

  /** Visitor over (uid, record). */
  @FunctionalInterface
  interface MessageVisitor {
    boolean visit(long uid, MessageRecord record) throws StorageException;
  }
}
