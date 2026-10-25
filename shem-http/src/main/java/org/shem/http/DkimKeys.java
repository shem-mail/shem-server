package org.shem.http;

import java.util.Optional;

/** DKIM key management as the admin API needs it (implemented by the outbound module). */
public interface DkimKeys {
  /**
   * Generates a key for a new selector and returns the TXT record value. Throws {@link
   * java.nio.file.FileAlreadyExistsException} if a key for the selector exists.
   */
  String generate(String selector, String domain) throws Exception;

  /** The TXT record value for an existing key, if any. */
  Optional<String> publishedRecord(String selector, String domain) throws Exception;
}
