package org.shem.search;

import org.shem.crypto.CryptoException;
import org.shem.mailbox.ExtensionContext;
import org.shem.mailbox.MailboxExtension;
import org.shem.mailbox.MailboxExtensionFactory;
import org.shem.store.StorageException;

/** Registers the encrypted search index as a mailbox extension. */
public final class SearchIndexFactory implements MailboxExtensionFactory {
  @Override
  public Class<? extends MailboxExtension> type() {
    return SearchIndex.class;
  }

  @Override
  public MailboxExtension open(ExtensionContext context) throws StorageException, CryptoException {
    return SearchIndex.open(context);
  }
}
