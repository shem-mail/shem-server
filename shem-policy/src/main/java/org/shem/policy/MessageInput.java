package org.shem.policy;

import java.io.IOException;
import java.io.InputStream;

/** A message that can be read more than once (memory buffer or encrypted spool). */
@FunctionalInterface
public interface MessageInput {
  InputStream open() throws IOException;
}
