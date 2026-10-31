package org.shem.store.metadata;

import org.shem.common.ImmutableBytes;
import org.shem.common.OpaqueId;
import org.shem.store.SpecialUse;
import org.shem.store.StorageException;

/**
 * A serialized write transaction. Reads observe the transaction's own changes. Nothing becomes
 * visible or durable unless the body returns normally and the journal append succeeds.
 */
public interface Tx extends ReadView {
  Folder createFolder(String name, SpecialUse specialUse) throws StorageException;

  void renameFolder(OpaqueId folderId, String newName) throws StorageException;

  void deleteFolder(OpaqueId folderId) throws StorageException;

  void setSubscribed(String name, boolean subscribed);

  /** Adds a message and returns its new UID. */
  long append(OpaqueId folderId, NewMessage message) throws StorageException;

  /** Adds a reference to the same blob under a new destination UID. */
  long copy(MessageKey source, OpaqueId destinationFolder) throws StorageException;

  /** Replaces flags; returns the new modseq. */
  long setFlags(MessageKey key, Flags flags) throws StorageException;

  void remove(MessageKey key) throws StorageException;

  void markReceiptImported(OpaqueId receiptId);

  void forgetReceipt(OpaqueId receiptId);

  /** Sets a property; an empty value removes it. */
  void setProperty(String key, ImmutableBytes value);
}
