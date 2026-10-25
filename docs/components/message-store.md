# Immutable Message Store

## Responsibility and Interfaces

Store encrypted message bytes and attachments as immutable files, preserving original MIME bytes apart from deliberate transport header changes. Offer bounded write/read streams to [delivery](delivery.md), [IMAP](imap.md), [search](search-index.md), and [export](http-api.md) through [cryptographic](cryptography.md) capabilities.

## On-Disk Contract

- Random opaque blob IDs and sharded random-ID directories; never subjects, addresses, folders, UIDs, or content hashes in paths.
- A versioned authenticated streaming format with bounded headers and independently authenticated access units where range reads require them. The chosen reviewed profile must authenticate completeness and expected length.
- Public format identifiers may be visible. Exact message length, parsed headers, envelope, MIME structure, and per-folder data belong to encrypted metadata/receipts, not plaintext file headers.
- Keep content-key envelopes separately replaceable, referenced by encrypted receipt/metadata records. Immutable blobs do not change when flags, folders, passwords, or ordinary key wrapping changes.

Writes use exclusive temporary names and publication only after a complete authenticated file is synced. Specify atomic-move and directory-sync requirements for supported filesystems. Temporary objects contain ciphertext only, use restrictive permissions, and are not mistaken for committed messages.

## Reading, References, and Removal

Reading requires an authorized mailbox view/key lease. Stream verified data and do not return bytes from a failed authentication unit as if trusted. Bound decrypted buffers, range requests, and caches; no mmap or plaintext file-backed cache.

COPY/MOVE creates or changes encrypted metadata references, not copies of the message file. [Metadata](metadata-store.md) owns logical references; the store deletes blobs only when no committed live reference, pending receipt, active reader, backup pin, or in-flight transaction requires them. Delayed reclamation prevents races around EXPUNGE.

Deleting a blob or envelope on current storage does not erase historical backups or SSD remnants. Removing envelopes from current metadata is not complete crypto-erase until old journal/snapshot/envelope copies are retired. Do not claim that rewrapping revokes a content key already exposed through an older envelope.

## Acceptance Checks

Round-trip synthetic MIME with large attachments and range reads; corrupt/truncate/reorder authenticated units; exhaust disk during writes; interrupt publication; race readers with COPY/EXPUNGE/GC. Plaintext-marker scans include temp paths. Password/flag/folder changes must not rewrite blob ciphertext.