package org.shem.identity;

/** Rejected identity operation. {@link Reason} maps to protocol/HTTP status codes. */
public final class IdentityException extends Exception {
  private static final long serialVersionUID = 1L;

  /** Machine-readable reason, never containing user data. */
  public enum Reason {
    NOT_FOUND,
    CONFLICT,
    VERSION_MISMATCH,
    INVALID,
    ALIAS_CYCLE,
    STORAGE
  }

  private final Reason reason;

  public IdentityException(Reason reason, String message) {
    super(message);
    this.reason = reason;
  }

  public IdentityException(Reason reason, String message, Throwable cause) {
    super(message, cause);
    this.reason = reason;
  }

  public Reason reason() {
    return reason;
  }
}
