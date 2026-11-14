package net.shem.search;

import net.shem.crypto.CryptoException;
import net.shem.mailbox.ExtensionContext;
import net.shem.mailbox.MailboxExtension;
import net.shem.mailbox.MailboxExtensionFactory;
import net.shem.store.StorageException;

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
