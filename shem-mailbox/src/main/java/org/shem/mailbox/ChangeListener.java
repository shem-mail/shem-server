package org.shem.mailbox;

/**
 * Notified after committed mailbox changes (imports, appends, flag changes) so sessions can send
 * untagged IMAP updates. Called outside the metadata lock; must not block.
 */
@FunctionalInterface
public interface ChangeListener {
  void changed(long txSeq);
}
