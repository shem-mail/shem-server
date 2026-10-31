package org.shem.store;

import org.shem.common.OpaqueId;

/**
 * Where a delivered message should be filed. Delivery while locked only knows symbolic roles or
 * opaque folder ids; folder names are resolved after unlock. Encrypted inside receipts.
 */
public sealed interface DeliveryTarget {
  /** File into the folder with this role, creating it on import if necessary. */
  record Role(SpecialUse role) implements DeliveryTarget {}

  /** File into a specific folder; falls back to INBOX if the folder no longer exists. */
  record Folder(OpaqueId folderId) implements DeliveryTarget {}
}
