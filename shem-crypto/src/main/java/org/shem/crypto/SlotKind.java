package org.shem.crypto;

/**
 * Kind of credential protecting a slot. The kind is visible in the slot file (needed to choose the
 * login path) and is part of the slot's authenticated context.
 */
public enum SlotKind {
  /** Short-lived administrator-issued credential before enrollment. */
  BOOTSTRAP(1),
  /** The user's primary password. */
  PASSWORD(2),
  /** Generated high-entropy app password for IMAP/SMTP clients. */
  APP(3),
  /** User-held offline recovery code. */
  RECOVERY(4);

  private final int code;

  SlotKind(int code) {
    this.code = code;
  }

  public int code() {
    return code;
  }

  public static SlotKind fromCode(int code) {
    for (SlotKind kind : values()) {
      if (kind.code == code) {
        return kind;
      }
    }
    throw new IllegalArgumentException("unknown slot kind");
  }
}
