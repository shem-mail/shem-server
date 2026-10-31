package org.shem.mailbox;

/**
 * The lease was revoked (logout, slot revocation, account blocking, shutdown) or released.
 * Unchecked because revocation is asynchronous; protocol adapters handle it once at their command
 * boundary by ending the session.
 */
public final class RevokedLeaseException extends RuntimeException {
  private static final long serialVersionUID = 1L;

  public RevokedLeaseException() {
    super("mailbox lease revoked");
  }
}
