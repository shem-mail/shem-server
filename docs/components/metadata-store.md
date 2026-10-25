# Encrypted Metadata Store

## Responsibility

Provide transactional per-mailbox folders, message membership, key-envelope references, replay checkpoints, and a bounded-memory on-disk lookup structure. Serve [IMAP](imap.md), [delivery replay](delivery.md), [search](search-index.md), [rotation](cryptography.md), and [backups](operations.md) without an external database.

## Data and Interfaces

- Folder ID/name, hierarchy, UIDVALIDITY, UIDNEXT, HIGHESTMODSEQ, subscriptions, and special-use roles.
- Per-folder message UID, blob ID, flags/keywords, internal date, size, modseq, and precomputed MIME envelope/bodystructure.
- Versioned key-envelope references, imported delivery IDs, index checkpoints, tombstones, and reference/reclamation information.
- Read views and serialized write transactions such as create/rename folder, append receipt, set flags, copy/move membership, expunge, and rotate envelope references.

All these values persist encrypted and authenticated. A filesystem folder is not an IMAP folder. Opaque structural/version information needed to find committed encrypted segments may remain visible; document its leakage.

## Storage and Concurrency Contract

Use append-only authenticated journal records, sealed immutable segments, and periodic encrypted snapshots plus immutable sorted lookup segments. Load recent blocks into a bounded decrypted cache; a login must not load the entire mailbox. The Phase 0 library-versus-own-segments decision must prove these properties rather than inherit unauthenticated database encryption.

One writer/coordinator per mailbox serializes UID/modseq allocation and reference changes. UIDNEXT never reuses a UID within a UIDVALIDITY epoch; sequence numbers are view-dependent and are not persisted as message identities. COPY allocates a new destination UID referring to the same blob; MOVE commits membership/reference updates together. Advertise CONDSTORE/QRESYNC only if the chosen James integration and persisted semantics support them.

Define an authenticated commit manifest linking the snapshot and sealed segments. Recover the last complete transaction; reject unauthenticated/corrupt committed state rather than treating it as an empty mailbox. Recovery of an incomplete active tail must be distinguishable from accepting a truncated committed segment. Maintain monotonic commit generations, while documenting that full-disk rollback needs external freshness state to detect.

Publish a snapshot atomically before retiring old segments, and respect active views/backup pins. New snapshot records drop obsolete envelopes/tombstones only after replay/GC safety requirements are met. The metadata index is rebuildable from a complete retained snapshot/journal chain, not from message ciphertext alone.

## Acceptance Checks

Exercise UID/UIDVALIDITY/modseq invariants, journal replay, authenticated corruption detection, every commit/snapshot crash point, concurrent folder/membership changes, and bounded memory for large synthetic mailboxes. Restore a snapshot plus sealed segments and prove stable message membership, flags, key references, and receipt deduplication.