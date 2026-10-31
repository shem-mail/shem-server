package org.shem.search;

import java.io.IOException;
import java.io.InputStream;
import org.jspecify.annotations.Nullable;

/**
 * Turns one attachment into bounded plain text (ADR 0019). Implementations run the parser outside
 * the server process; this interface only sees bytes, a declared content type, and a file-name
 * extension as non-sensitive hints.
 */
public interface AttachmentExtractor {
  /** The result for one attachment. */
  sealed interface Outcome {
    /** Extracted text; {@code truncated} when the output limit cut it short. */
    record Text(String text, boolean truncated) implements Outcome {}

    /** No supported parser for the detected format. */
    record Unsupported() implements Outcome {}

    /** Password-protected or encrypted; never decrypted. */
    record Encrypted() implements Outcome {}

    /** A size, time, depth, or expansion limit stopped extraction. */
    record LimitReached(String limit) implements Outcome {}

    /** The parser failed on this input. */
    record Failed() implements Outcome {}
  }

  /** Thrown when no worker can run right now (startup failure, shutdown); retry later. */
  final class UnavailableException extends Exception {
    private static final long serialVersionUID = 1L;

    public UnavailableException(String message) {
      super(message);
    }

    public UnavailableException(String message, Throwable cause) {
      super(message, cause);
    }
  }

  /**
   * Extracts {@code content} (decoded attachment bytes, read here up to the implementation's input
   * limit; a longer stream yields {@link Outcome.LimitReached}).
   */
  Outcome extract(InputStream content, @Nullable String contentType, @Nullable String extension)
      throws UnavailableException, InterruptedException, IOException;
}
