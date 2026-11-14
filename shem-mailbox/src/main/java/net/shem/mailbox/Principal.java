package net.shem.mailbox;

import java.util.Set;
import net.shem.common.OpaqueId;
import net.shem.crypto.SlotKind;
import net.shem.identity.EmailAddress;

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
