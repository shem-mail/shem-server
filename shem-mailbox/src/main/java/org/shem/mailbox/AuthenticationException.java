package org.shem.mailbox;

import java.time.Duration;
import org.jspecify.annotations.Nullable;

/**
 * Authentication did not produce a session. {@link Reason#INVALID} deliberately covers unknown
 * users, wrong credentials, disabled accounts, and expired bootstrap credentials alike.
 */
public final class AuthenticationException extends Exception {
  private static final long serialVersionUID = 1L;

  /** Externally visible failure class. */
  public enum Reason {
    INVALID,
    /** Source temporarily blocked or KDF capacity exhausted; retry later. */
    THROTTLED,
    /** Credential valid but lacks the capability for this protocol (for example bootstrap). */
    NOT_PERMITTED,
    /** Storage failure while unlocking. */
    UNAVAILABLE
  }

  private final Reason reason;
  private final @Nullable Duration retryAfter;

  public AuthenticationException(Reason reason, @Nullable Duration retryAfter) {
    super(reason.name());
    this.reason = reason;
    this.retryAfter = retryAfter;
  }

  public Reason reason() {
    return reason;
  }

  public @Nullable Duration retryAfter() {
    return retryAfter;
  }
}
