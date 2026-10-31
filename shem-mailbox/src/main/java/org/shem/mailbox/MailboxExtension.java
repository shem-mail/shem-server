package org.shem.mailbox;

/**
 * Per-mailbox component that lives exactly as long as the mailbox is unlocked (for example the
 * encrypted search index). It never keeps the mailbox unlocked by itself: the coordinator closes it
 * when the last lease is released, and restarts it after re-encryption under a new data key.
 */
public interface MailboxExtension extends AutoCloseable {
  @Override
  void close();
}
