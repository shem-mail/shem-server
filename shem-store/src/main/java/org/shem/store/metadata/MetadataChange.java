package org.shem.store.metadata;

import org.shem.common.OpaqueId;

/**
 * A committed metadata change, delivered to commit listeners after the journal append so that
 * protocol sessions (IMAP IDLE, selected-mailbox state) can update. In-memory only.
 */
public sealed interface MetadataChange {
  record FolderCreated(Folder folder) implements MetadataChange {}

  record FolderRenamed(OpaqueId folderId, String oldName, String newName)
      implements MetadataChange {}

  record FolderDeleted(Folder folder) implements MetadataChange {}

  record MessageAdded(MessageKey key, MessageRecord record) implements MetadataChange {}

  record FlagsChanged(MessageKey key, Flags oldFlags, Flags newFlags, long modSeq)
      implements MetadataChange {}

  record MessageRemoved(MessageKey key, MessageRecord removed) implements MetadataChange {}
}
