package org.shem.store.metadata;

import org.shem.common.OpaqueId;
import org.shem.store.SpecialUse;

/**
 * An IMAP folder. Folders are metadata rows, never filesystem directories. {@code uidNext} never
 * decreases within a UIDVALIDITY epoch.
 */
public record Folder(
    OpaqueId folderId, String name, long uidValidity, long uidNext, SpecialUse specialUse) {
  public static final int MAX_NAME_BYTES = 1024;

  public Folder {
    if (name.isEmpty()
        || name.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > MAX_NAME_BYTES) {
      throw new IllegalArgumentException("invalid folder name");
    }
    if (uidValidity <= 0 || uidValidity > 0xffffffffL || uidNext < 1 || uidNext > 0x100000000L) {
      throw new IllegalArgumentException("invalid folder counters");
    }
  }

  Folder withName(String newName) {
    return new Folder(folderId, newName, uidValidity, uidNext, specialUse);
  }

  Folder withUidNext(long next) {
    return new Folder(folderId, name, uidValidity, Math.max(uidNext, next), specialUse);
  }
}
