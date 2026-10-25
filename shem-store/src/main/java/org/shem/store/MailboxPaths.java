package org.shem.store;

import java.nio.file.Path;
import org.shem.common.OpaqueId;

/**
 * On-disk layout of mailboxes: {@code <root>/<aa>/<bd>/<mailboxId>/} with fixed subdirectories.
 * Only opaque random identifiers appear in paths.
 */
public final class MailboxPaths {
  private final Path root;

  public MailboxPaths(Path root) {
    this.root = root.toAbsolutePath();
  }

  public Path root() {
    return root;
  }

  public Path mailbox(OpaqueId mailboxId) {
    return root.resolve(mailboxId.shardPath()).resolve(mailboxId.value());
  }

  public Path keys(OpaqueId mailboxId) {
    return mailbox(mailboxId).resolve("keys");
  }

  public Path blobs(OpaqueId mailboxId) {
    return mailbox(mailboxId).resolve("blobs");
  }

  public Path receipts(OpaqueId mailboxId) {
    return mailbox(mailboxId).resolve("receipts");
  }

  public Path metadata(OpaqueId mailboxId) {
    return mailbox(mailboxId).resolve("metadata");
  }

  public Path index(OpaqueId mailboxId) {
    return mailbox(mailboxId).resolve("index");
  }
}
