package net.shem.search;

import net.shem.crypto.CryptoException;
import net.shem.mailbox.ExtensionContext;
import net.shem.mailbox.MailboxExtension;
import net.shem.mailbox.MailboxExtensionFactory;
import net.shem.store.StorageException;

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
