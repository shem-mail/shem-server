package org.shem.store;

/**
 * Storage failure. {@link Kind#CORRUPT} means authenticated data failed verification and must never
 * be treated as empty; {@link Kind#UNAVAILABLE} covers I/O errors such as a full disk and maps to
 * temporary protocol failures.
 */
public final class StorageException extends Exception {
  private static final long serialVersionUID = 1L;

  /** Failure class. */
  public enum Kind {
    CORRUPT,
    UNAVAILABLE,
    NOT_FOUND,
    LIMIT_EXCEEDED,
    CONFLICT
  }

  private final Kind kind;

  public StorageException(Kind kind, String message) {
    super(message);
    this.kind = kind;
  }

  public StorageException(Kind kind, String message, Throwable cause) {
    super(message, cause);
    this.kind = kind;
  }

  public Kind kind() {
    return kind;
  }
}
