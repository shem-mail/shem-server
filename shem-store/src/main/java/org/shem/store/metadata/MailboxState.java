package org.shem.store.metadata;

import java.util.HashMap;
import java.util.Map;
import java.util.NavigableMap;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import org.jspecify.annotations.Nullable;
import org.shem.common.ImmutableBytes;
import org.shem.common.OpaqueId;

/**
 * In-memory mutable state above a snapshot: small tables (folders, subscriptions, properties,
 * receipt checkpoints) in full, plus a message delta since the snapshot. Message entries that did
 * not change since the snapshot stay on disk and are read through the block cache.
 */
final class MailboxState {
  /** Marker for an entry removed since the snapshot. */
  static final MessageRecord TOMBSTONE =
      new MessageRecord(
          new OpaqueId("00000000000000000000000000000000"),
          ImmutableBytes.EMPTY,
          0,
          0,
          1,
          Flags.NONE,
          ImmutableBytes.EMPTY);

  long txSeq;

  @SuppressWarnings("ReferenceEquality") // identity marks the sentinel, not record contents
  static boolean isTombstone(@Nullable MessageRecord record) {
    return record == TOMBSTONE;
  }

  long modSeq;
  final Map<OpaqueId, Folder> folders = new HashMap<>();
  final Set<String> subscriptions = new TreeSet<>();
  final Map<String, ImmutableBytes> properties = new TreeMap<>();
  final Map<OpaqueId, Long> importedReceipts = new HashMap<>();
  final NavigableMap<MessageKey, MessageRecord> delta = new TreeMap<>();
  long deltaOps;

  /** Applies a resolved op. Must be deterministic: used for live commits and replay. */
  void apply(Op op, @Nullable SnapshotReader base) {
    deltaOps++;
    switch (op) {
      case Op.CreateFolder c -> folders.put(c.folder().folderId(), c.folder());
      case Op.RenameFolder r -> {
        Folder f = folders.get(r.folderId());
        if (f != null) {
          folders.put(r.folderId(), f.withName(r.name()));
        }
      }
      case Op.DeleteFolder d -> {
        folders.remove(d.folderId());
        delta
            .subMap(MessageKey.first(d.folderId()), true, MessageKey.last(d.folderId()), true)
            .clear();
      }
      case Op.Subscribe s -> {
        if (s.subscribed()) {
          subscriptions.add(s.name());
        } else {
          subscriptions.remove(s.name());
        }
      }
      case Op.PutMessage p -> {
        delta.put(p.key(), p.record());
        modSeq = Math.max(modSeq, p.record().modSeq());
        Folder f = folders.get(p.key().folderId());
        if (f != null) {
          folders.put(f.folderId(), f.withUidNext(p.key().uid() + 1));
        }
      }
      case Op.SetFlags s -> {
        MessageRecord current = lookup(s.key(), base);
        if (current != null) {
          delta.put(s.key(), current.withFlags(s.flags(), s.modSeq()));
        }
        modSeq = Math.max(modSeq, s.modSeq());
      }
      case Op.RemoveMessage r -> {
        delta.put(r.key(), TOMBSTONE);
        modSeq = Math.max(modSeq, r.modSeq());
      }
      case Op.ReceiptImported r -> importedReceipts.put(r.receiptId(), r.importedAtMillis());
      case Op.ForgetReceipt f -> importedReceipts.remove(f.receiptId());
      case Op.SetProperty p -> {
        if (p.value().length() == 0) {
          properties.remove(p.key());
        } else {
          properties.put(p.key(), p.value());
        }
      }
    }
  }

  @Nullable MessageRecord lookup(MessageKey key, @Nullable SnapshotReader base) {
    if (!folders.containsKey(key.folderId())) {
      return null;
    }
    MessageRecord changed = delta.get(key);
    if (changed != null) {
      return isTombstone(changed) ? null : changed;
    }
    return base == null ? null : base.lookup(key).orElse(null);
  }

  Optional<Folder> folderByName(String name) {
    return folders.values().stream().filter(f -> f.name().equals(name)).findFirst();
  }
}
