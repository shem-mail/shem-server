package org.shem.delivery;

import java.io.IOException;
import java.io.InputStream;

/** A re-readable message body, read once per recipient. */
public interface MessageSource {
  InputStream open() throws IOException;

  long size();

  /** In-memory source for small messages (local submission, DSNs, tests). */
  static MessageSource ofBytes(byte[] bytes) {
    byte[] copy = bytes.clone();
    return new MessageSource() {
      @Override
      public InputStream open() {
        return new java.io.ByteArrayInputStream(copy);
      }

      @Override
      public long size() {
        return copy.length;
      }
    };
  }
}
