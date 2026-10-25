package org.shem.identity;

/** Account lifecycle. Transitions are validated by {@link #canTransitionTo(AccountState)}. */
public enum AccountState {
  /** Created by an administrator; only bootstrap credentials exist. */
  PENDING_ENROLLMENT(1),
  ACTIVE(2),
  /** No authentication; delivery follows the configured blocked-delivery policy. */
  BLOCKED(3),
  /** Waiting period before crypto-erase; no authentication or delivery. */
  DELETION_PENDING(4),
  /** Keys and mailbox removed; the record stays as a tombstone reserving the address. */
  DELETED(5);

  private final int code;

  AccountState(int code) {
    this.code = code;
  }

  public int code() {
    return code;
  }

  public static AccountState fromCode(int code) {
    for (AccountState state : values()) {
      if (state.code == code) {
        return state;
      }
    }
    throw new IllegalArgumentException("unknown account state");
  }

  public boolean canTransitionTo(AccountState next) {
    return switch (this) {
      case PENDING_ENROLLMENT -> next == ACTIVE || next == BLOCKED || next == DELETION_PENDING;
      case ACTIVE -> next == BLOCKED || next == DELETION_PENDING;
      case BLOCKED -> next == ACTIVE || next == DELETION_PENDING || next == PENDING_ENROLLMENT;
      case DELETION_PENDING -> next == DELETED || next == ACTIVE || next == BLOCKED;
      case DELETED -> false;
    };
  }

  public boolean allowsAuthentication() {
    return this == PENDING_ENROLLMENT || this == ACTIVE;
  }
}
