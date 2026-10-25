# Encrypted Delivery

## Responsibility

Durably deliver to a mailbox using only its public key, whether locked or unlocked. Connect [inbound](smtp-inbound.md), local [submission](smtp-submission.md), and DSNs from [outbound](outbound-delivery.md) to [message](message-store.md) and [metadata](metadata-store.md) storage. Never allocate IMAP UIDs by reading private state while locked.

## Receipt and Commit Contract

Input: opaque recipient ID, routing/key version, bounded message stream, internal delivery ID, flags, internal date, envelope/policy results, and symbolic/opaque target folder. Recipient addresses, targets, flags, and all other private receipt fields are encrypted with a fresh receipt key enveloped to the recipient public key.

1. Validate account/key generation and reserve physical quota through [identity](identity.md).
2. Write and sync a complete immutable encrypted blob using [cryptography](cryptography.md).
3. Write a versioned encrypted receipt identifying the blob and its envelope, then commit/sync the receipt and required directory/manifest state on the supported filesystem.
4. Return a durable acknowledgement only after both objects are recoverable. Notify an active mailbox coordinator without making that notification part of durability.

Use per-recipient randomized ciphertext/envelopes initially; do not add cross-user content-addressable deduplication. Any later sharing needs an explicit leakage/key-isolation decision. Coordinate key-version changes so a receipt remains unwrap-able across enrollment and rotation.

## Replay and Garbage Collection

On unlock, decrypt pending receipts in a stable internal sequence and submit ordinary metadata transactions to the single mailbox writer. Resolve folders, assign UIDs, add flags/summaries, and enqueue indexing only then. Record imported delivery IDs atomically with metadata updates before checkpointing/removing receipts.

Receipt replay is idempotent for the same internal delivery ID. A remote SMTP retry is a new transaction and is not safely identifiable by Message-ID alone. Snapshot compaction must preserve replay checkpoints until old receipts cannot return in a valid restore.

A crash may leave orphan ciphertext, an unimported receipt, or an imported receipt awaiting retirement. Recovery must distinguish these using committed manifests/reference state, not plaintext folder metadata. Garbage collection uses a grace period and excludes in-flight writes and retained backup views. A missing referenced blob is an integrity failure, never a silently skipped delivery.

## Acceptance Checks

Deliver to a locked mailbox with no private key accessible. Inject failure before/after every sync, receipt publication, metadata import, and checkpoint. Recovery must retain every acknowledged delivery exactly once per internal ID. Test concurrent replay, login/logout, quota changes, local multi-recipient sends, and public-key rotation.