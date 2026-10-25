package org.shem.mailbox;

import java.util.Set;
import org.shem.common.OpaqueId;
import org.shem.crypto.SlotKind;
import org.shem.identity.EmailAddress;

/** An authenticated mailbox user, bound to the slot that unlocked the session. */
public record Principal(
    OpaqueId mailboxId,
    EmailAddress address,
    OpaqueId slotId,
    SlotKind slotKind,
    Set<Capability> capabilities) {
  public Principal {
    capabilities = Set.copyOf(capabilities);
  }

  public boolean can(Capability capability) {
    return capabilities.contains(capability);
  }
}
