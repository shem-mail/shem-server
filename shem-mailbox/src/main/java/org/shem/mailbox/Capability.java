package org.shem.mailbox;

import java.util.EnumSet;
import java.util.Set;
import org.shem.crypto.SlotKind;

/** What an authenticated principal may do, derived from the slot it unlocked. */
public enum Capability {
  /** Read and modify mailbox contents (IMAP, export). */
  MAIL_ACCESS,
  /** Submit mail. */
  SUBMIT,
  /** Change passwords, manage app passwords and recovery codes, rotate keys. */
  KEY_ADMINISTRATION,
  /** Complete mandatory enrollment; the only capability of bootstrap credentials. */
  ENROLL;

  public static Set<Capability> forSlot(SlotKind kind) {
    return switch (kind) {
      case BOOTSTRAP -> EnumSet.of(ENROLL);
      case PASSWORD -> EnumSet.of(MAIL_ACCESS, SUBMIT, KEY_ADMINISTRATION);
      case APP -> EnumSet.of(MAIL_ACCESS, SUBMIT);
      case RECOVERY -> EnumSet.of(KEY_ADMINISTRATION);
    };
  }
}
