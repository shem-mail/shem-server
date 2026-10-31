package org.shem.imap;

import org.apache.james.mailbox.model.MailboxId;
import org.apache.james.mailbox.model.MessageId;
import org.jspecify.annotations.Nullable;
import org.shem.common.OpaqueId;

/** James identifier types backed by Shem's opaque ids. */
final class Ids {
  private Ids() {}

  /** A folder id as a James mailbox id. */
  record FolderId(OpaqueId id) implements MailboxId {
    @Override
    public String serialize() {
      return id.value();
    }

    @Override
    public String toString() {
      return "FolderId[" + id.value().substring(0, 4) + "…]";
    }
  }

  /** A blob id as a James message id: the same message copied to several folders shares it. */
  record BlobId(OpaqueId id) implements MessageId {
    @Override
    public String serialize() {
      return id.value();
    }

    @Override
    public boolean isSerializable() {
      return true;
    }
  }

  static final MailboxId.Factory MAILBOX_IDS =
      serialized -> {
        OpaqueId id = OpaqueId.parseOrNull(serialized);
        if (id == null) {
          throw new IllegalArgumentException("malformed mailbox id");
        }
        return new FolderId(id);
      };

  static final MessageId.Factory MESSAGE_IDS =
      new MessageId.Factory() {
        @Override
        public MessageId fromString(String serialized) {
          OpaqueId id = OpaqueId.parseOrNull(serialized);
          if (id == null) {
            throw new IllegalArgumentException("malformed message id");
          }
          return new BlobId(id);
        }

        @Override
        public MessageId generate() {
          throw new UnsupportedOperationException("message ids are assigned by the store");
        }
      };

  static OpaqueId folderOf(@Nullable MailboxId id)
      throws org.apache.james.mailbox.exception.MailboxNotFoundException {
    if (id instanceof FolderId folder) {
      return folder.id();
    }
    throw new org.apache.james.mailbox.exception.MailboxNotFoundException("unknown mailbox id");
  }
}
