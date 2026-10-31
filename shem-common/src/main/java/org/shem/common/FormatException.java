package org.shem.common;

/**
 * Persisted data is malformed, truncated, of an unknown version, or failed authentication.
 *
 * <p>Callers must treat this as corruption, never as an empty or missing object. Messages are fixed
 * descriptions and never contain user data.
 */
public class FormatException extends Exception {
  private static final long serialVersionUID = 1L;

  public FormatException(String message) {
    super(message);
  }

  public FormatException(String message, Throwable cause) {
    super(message, cause);
  }
}
