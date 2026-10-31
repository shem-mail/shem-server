# ADR 0004: Own Authenticated Metadata Segments

Status: accepted.

## Context

Whitepaper 5.10 asks whether to build sorted segments or adapt a library (Xodus, H2 MVStore). Their built-in encryption uses one database key without authenticated integrity and rewrites mutable files, which conflicts with per-mailbox key hierarchy, immutable sealed files, and backup consistency.

## Decision

`shem-store` implements per-mailbox metadata as:

- **Journal segments** `seg-<id>`: plaintext header (format, profile, mailbox id, segment id, data version) then records `u32 length || AES-GCM(segmentKey, payload)`. The segment key is HKDF-derived from the data root and segment id; each record's AAD binds mailbox, segment, and record index. A transaction is one record with a strictly consecutive sequence number. Segments are sealed with a final record carrying the record count.
- **Snapshots** `snap-<id>`: one streaming-AEAD ciphertext containing header tables (folders, subscriptions, properties, receipt checkpoints), sorted message blocks (≤128 entries / 64 KiB), a block index, and a trailer. Lookups decrypt only the needed blocks through a bounded LRU cache.
- **Manifest** `manifest`: atomically replaced; plaintext header with data version and generation, AES-GCM body naming the snapshot, sealed segments, and active segment.

Recovery replays sealed segments then the active segment. A final record that extends past end-of-file is a torn write and is truncated; a complete record failing authentication, a missing referenced file, a sequence gap, or an unsealed "sealed" segment fails with `CORRUPT` — never an empty mailbox. Compaction writes a new snapshot and segment, publishes the manifest, and only then deletes unreferenced files (unless pinned for backup). Re-encryption is compaction under a new data root with a record transform that rewraps content keys.

One writer per mailbox is enforced in-process by `MailboxRegistry` and across processes by an exclusive file lock.

## Evidence

`MetadataStoreTest`: restart persistence, UID non-reuse after expunge/compaction, aborted transactions, journal append failure, torn tail vs. corrupt record, missing snapshot/garbled manifest, wrong data key, crash before/after the compaction manifest, 10 000-message mailbox across segment rolls and compaction with a 4-block cache, re-encryption, double open, receipt checkpoints. Plaintext-marker scans over store directories.

## Visible leakage

File names are opaque ids; sizes, counts, and modification times of segments/snapshots reveal activity and approximate mailbox size. Truncating the active segment at a record boundary or restoring an older valid manifest+files is not detectable without external freshness state.
