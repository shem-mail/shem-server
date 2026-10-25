package org.shem.mailbox;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.jspecify.annotations.Nullable;
import org.shem.common.DurableFiles;
import org.shem.common.FormatException;
import org.shem.common.OpaqueId;
import org.shem.crypto.Argon2Parameters;
import org.shem.crypto.KeySlot;
import org.shem.crypto.SlotKind;
import org.shem.store.MailboxPaths;
import org.shem.store.StorageException;

/**
 * Persistence of credential slots and the sealed keyring under {@code <mailbox>/keys/}.
 *
 * <p>Slot files are named {@code slot-<kind>-<selector>-<slotId>}. The kind and the app-password
 * selector are visible by design (they pick the slot without trying every one); the selector is not
 * part of the app password's secret entropy. The keyring file is authoritative: slot files it does
 * not list are stale leftovers of interrupted changes and are removed on unlock.
 */
final class KeyFiles {
  static final String NO_SELECTOR = "0000";
  private static final String KEYRING = "keyring";

  private final MailboxPaths paths;
  private final Argon2Parameters.Limits limits;

  KeyFiles(MailboxPaths paths, Argon2Parameters.Limits limits) {
    this.paths = paths;
    this.limits = limits;
  }

  record StoredSlot(KeySlot slot, String selector, Path file) {}

  /** Slots of the given kinds, optionally restricted to one selector. */
  List<StoredSlot> slots(OpaqueId mailboxId, List<SlotKind> kinds, @Nullable String selector)
      throws StorageException {
    Path directory = paths.keys(mailboxId);
    List<StoredSlot> result = new ArrayList<>();
    if (!Files.isDirectory(directory)) {
      return result;
    }
    try (var files = Files.list(directory)) {
      for (Path file : (Iterable<Path>) files::iterator) {
        List<String> parts = List.of(String.valueOf(file.getFileName()).split("-", -1));
        if (parts.size() != 4 || !parts.get(0).equals("slot")) {
          continue;
        }
        SlotKind kind;
        try {
          kind = SlotKind.fromCode(Integer.parseInt(parts.get(1)));
        } catch (IllegalArgumentException e) {
          continue;
        }
        if (!kinds.contains(kind) || (selector != null && !selector.equals(parts.get(2)))) {
          continue;
        }
        KeySlot slot = KeySlot.decode(Files.readAllBytes(file), limits);
        if (!slot.mailboxId().equals(mailboxId)
            || slot.kind() != kind
            || !slot.slotId().value().equals(parts.get(3))) {
          throw new StorageException(StorageException.Kind.CORRUPT, "slot file mismatch");
        }
        result.add(new StoredSlot(slot, parts.get(2), file));
      }
    } catch (IOException e) {
      throw new StorageException(StorageException.Kind.UNAVAILABLE, "slot listing failed", e);
    } catch (FormatException e) {
      throw new StorageException(StorageException.Kind.CORRUPT, "slot file malformed", e);
    }
    result.sort(
        java.util.Comparator.comparingLong((StoredSlot s) -> lastModified(s.file())).reversed());
    return result;
  }

  List<StoredSlot> allSlots(OpaqueId mailboxId) throws StorageException {
    return slots(mailboxId, List.of(SlotKind.values()), null);
  }

  void writeSlot(KeySlot slot, String selector) throws StorageException {
    try {
      Path directory = DurableFiles.createPrivateDirectories(paths.keys(slot.mailboxId()));
      DurableFiles.writeNew(directory.resolve(fileName(slot, selector)), slot.encode());
    } catch (IOException e) {
      throw new StorageException(StorageException.Kind.UNAVAILABLE, "slot write failed", e);
    }
  }

  void deleteSlotFile(Path file) throws StorageException {
    try {
      DurableFiles.deleteDurably(file);
    } catch (IOException e) {
      throw new StorageException(StorageException.Kind.UNAVAILABLE, "slot delete failed", e);
    }
  }

  byte[] readKeyring(OpaqueId mailboxId) throws StorageException {
    try {
      return Files.readAllBytes(paths.keys(mailboxId).resolve(KEYRING));
    } catch (NoSuchFileException e) {
      throw new StorageException(StorageException.Kind.CORRUPT, "keyring missing", e);
    } catch (IOException e) {
      throw new StorageException(StorageException.Kind.UNAVAILABLE, "keyring read failed", e);
    }
  }

  /** Atomically replaces the keyring: the commit point of every key-lifecycle change. */
  void writeKeyring(OpaqueId mailboxId, byte[] sealed) throws StorageException {
    try {
      Path directory = DurableFiles.createPrivateDirectories(paths.keys(mailboxId));
      DurableFiles.writeAtomically(directory.resolve(KEYRING), sealed);
    } catch (IOException e) {
      throw new StorageException(StorageException.Kind.UNAVAILABLE, "keyring write failed", e);
    }
  }

  static String fileName(KeySlot slot, String selector) {
    return "slot-" + slot.kind().code() + "-" + selector + "-" + slot.slotId().value();
  }

  private static long lastModified(Path file) {
    try {
      return Files.getLastModifiedTime(file).toMillis();
    } catch (IOException e) {
      return 0;
    }
  }
}
