package org.shem.crypto;

/**
 * A cryptographic operation failed: wrong key/credential, tampering, truncation, or an unsupported
 * format. Messages never include key material or user data.
 */
public class CryptoException extends Exception {
  private static final long serialVersionUID = 1L;

  public CryptoException(String message) {
    super(message);
  }

  public CryptoException(String message, Throwable cause) {
    super(message, cause);
  }
}
