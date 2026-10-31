package org.shem.search;

import org.shem.crypto.CryptoException;
import org.shem.mailbox.ExtensionContext;
import org.shem.mailbox.MailboxExtension;
import org.shem.mailbox.MailboxExtensionFactory;
import org.shem.store.StorageException;

/** Registers the attachment index (ADR 0019) with the extractor it uses. */
public final class AttachmentIndexFactory implements MailboxExtensionFactory {
  private final AttachmentExtractor extractor;

  public AttachmentIndexFactory(AttachmentExtractor extractor) {
    this.extractor = extractor;
  }

  @Override
  public Class<? extends MailboxExtension> type() {
    return AttachmentIndex.class;
  }

  @Override
  public MailboxExtension open(ExtensionContext context) throws StorageException, CryptoException {
    return AttachmentIndex.open(context, extractor);
  }
}
