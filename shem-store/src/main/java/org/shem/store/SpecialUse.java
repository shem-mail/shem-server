package org.shem.store;

/** Special-use folder roles (RFC 6154 plus INBOX). Delivery targets folders by role. */
public enum SpecialUse {
  NONE(0),
  INBOX(1),
  SENT(2),
  DRAFTS(3),
  TRASH(4),
  JUNK(5),
  ARCHIVE(6);

  private final int code;

  SpecialUse(int code) {
    this.code = code;
  }

  public int code() {
    return code;
  }

  public static SpecialUse fromCode(int code) {
    for (SpecialUse use : values()) {
      if (use.code == code) {
        return use;
      }
    }
    throw new IllegalArgumentException("unknown special use");
  }
}
