package org.shem.mailbox;

import org.shem.crypto.CryptoException;
import org.shem.store.StorageException;

/** Creates an extension instance for each unlocked mailbox. */
public interface MailboxExtensionFactory {
  /** Type under which the extension is looked up via {@link MailboxLease#extension(Class)}. */
  Class<? extends MailboxExtension> type();

  /** Opens the extension; it must not retain {@code context} beyond its own lifetime. */
  MailboxExtension open(ExtensionContext context) throws StorageException, CryptoException;
}
