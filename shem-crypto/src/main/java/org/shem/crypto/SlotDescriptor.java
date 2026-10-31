package org.shem.crypto;

import java.time.Instant;
import org.shem.common.OpaqueId;

/**
 * Non-secret description of a credential slot. Labels are user data and are therefore persisted
 * only inside the encrypted keyring, never in the slot file.
 */
public record SlotDescriptor(OpaqueId slotId, SlotKind kind, String label, Instant createdAt) {
  public static final int MAX_LABEL_BYTES = 128;

  public SlotDescriptor {
    if (label.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > MAX_LABEL_BYTES) {
      throw new IllegalArgumentException("label too long");
    }
  }
}
