package net.shem.mailbox;

import net.shem.common.ImmutableBytes;
import net.shem.common.OpaqueId;
import net.shem.crypto.AssociatedData;
import net.shem.crypto.CryptoException;
import net.shem.crypto.Purpose;
import net.shem.crypto.SymmetricKey;

/**
 * Wraps per-message content keys for metadata records under a key derived from the mailbox data
 * root. The wrap is bound to mailbox, blob, and data version; re-encryption rewraps every record.
 */
final class ContentKeys {
  private static final int FORMAT = 1;

  private ContentKeys() {}

  static SymmetricKey wrappingKey(SymmetricKey dataRoot, OpaqueId mailboxId)
      throws CryptoException {
    return dataRoot.derive(Purpose.CONTENT_KEY_WRAP, mailboxId.toBytes());
  }

  static ImmutableBytes wrap(
      SymmetricKey wrappingKey,
      OpaqueId mailboxId,
      OpaqueId blobId,
      int dataVersion,
      SymmetricKey contentKey)
      throws CryptoException {
    return ImmutableBytes.copyOf(
        wrappingKey.wrapKey(contentKey, context(mailboxId, blobId, dataVersion)));
  }

  static SymmetricKey unwrap(
      SymmetricKey wrappingKey,
      OpaqueId mailboxId,
      OpaqueId blobId,
      int dataVersion,
      ImmutableBytes wrapped)
      throws CryptoException {
    return wrappingKey.unwrapKey(wrapped.toByteArray(), context(mailboxId, blobId, dataVersion));
  }

  private static AssociatedData context(OpaqueId mailboxId, OpaqueId blobId, int dataVersion) {
    return AssociatedData.builder(Purpose.CONTENT_KEY_WRAP, FORMAT)
        .id("mailbox", mailboxId)
        .id("blob", blobId)
        .number("dataVersion", dataVersion)
        .build();
  }
}
