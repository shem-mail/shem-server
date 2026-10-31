package org.shem.store.metadata;

import org.shem.common.OpaqueId;

/** Message identity within a folder: (folder id, UID). */
public record MessageKey(OpaqueId folderId, long uid) implements Comparable<MessageKey> {
  @Override
  public int compareTo(MessageKey other) {
    int byFolder = folderId.compareTo(other.folderId);
    return byFolder != 0 ? byFolder : Long.compare(uid, other.uid);
  }

  static MessageKey first(OpaqueId folderId) {
    return new MessageKey(folderId, 0);
  }

  static MessageKey last(OpaqueId folderId) {
    return new MessageKey(folderId, Long.MAX_VALUE);
  }
}
