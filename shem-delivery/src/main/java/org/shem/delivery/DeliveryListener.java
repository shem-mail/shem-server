package org.shem.delivery;

import org.shem.common.OpaqueId;

/**
 * Notified after a durable delivery so an unlocked mailbox can import promptly. Notification is not
 * part of durability; implementations must not block.
 */
@FunctionalInterface
public interface DeliveryListener {
  DeliveryListener NONE = mailboxId -> {};

  void delivered(OpaqueId mailboxId);
}
