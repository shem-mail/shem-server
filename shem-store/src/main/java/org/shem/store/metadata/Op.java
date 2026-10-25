package org.shem.store.metadata;

import org.shem.common.ImmutableBytes;
import org.shem.common.OpaqueId;

/** Resolved, persisted metadata operations. Codes are part of the journal format. */
sealed interface Op {
  record CreateFolder(Folder folder) implements Op {}

  record RenameFolder(OpaqueId folderId, String name) implements Op {}

  record DeleteFolder(OpaqueId folderId) implements Op {}

  record Subscribe(String name, boolean subscribed) implements Op {}

  record PutMessage(MessageKey key, MessageRecord record) implements Op {}

  record SetFlags(MessageKey key, Flags flags, long modSeq) implements Op {}

  record RemoveMessage(MessageKey key, long modSeq) implements Op {}

  record ReceiptImported(OpaqueId receiptId, long importedAtMillis) implements Op {}

  record ForgetReceipt(OpaqueId receiptId) implements Op {}

  record SetProperty(String key, ImmutableBytes value) implements Op {}
}
