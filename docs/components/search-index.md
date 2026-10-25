# Search and Encrypted Lucene

## Responsibility and Collaborators

Answer complete IMAP SEARCH through an encrypted per-mailbox Lucene index plus exact fallback evaluation. Use [metadata](metadata-store.md) for folder membership/flags, [blobs](message-store.md) for message content, [extraction](attachment-extraction.md) for attachment text, and [session leases](sessions.md) for unlocked access.

## Encrypted Directory Contract

Implement Lucene Directory/IndexInput/IndexOutput semantics over reviewed authenticated random-access encryption. Cover clone/slice/seek, checksums, file length, listing, sync, rename, deletion, locking, and commit files for the pinned Lucene version. Do not assume a FilterDirectory wrapper alone intercepts all relevant plaintext or that Lucene never needs mutable bookkeeping.

Use fresh per-file keys/nonces and authenticated block context binding file generation, block index, and length. Random reads must not require decrypting the whole file. No mmap. File names/commit metadata must not reveal mailbox terms or stored field names; document any remaining technical Lucene naming leakage. All temp/merge/lock artifacts must be inspected for plaintext.

Maintain a bounded, wipe-on-close decrypted block cache and no persistent plaintext caches. Lucene checksums are not a substitute for AEAD integrity. Treat authentication failure as corruption, not an empty result.

## Indexing and Query Semantics

Index immutable searchable message content and headers; extract attachment text without storing that text as a retrievable field. Mutable flags and membership stay in metadata. Store stable opaque message identifiers, then project results into the queried folder's UID view.

Maintain a committed coverage watermark or equivalent coverage set bound to a metadata generation. For each search view, union committed-index candidates with exact evaluation of uncovered messages, and apply flags/membership predicates against that same view. Handle boolean operators, NOT, deletions, charset/date semantics, and analyzer false negatives: candidate generation must be conservative and exact evaluation must match supported IMAP semantics, not merely Lucene token matching.

Index asynchronously under cancellable bounded leases. A failed extraction/index update cannot advance coverage past missing content. Decide attachment-search failure semantics explicitly; return an error when a promised search scope cannot be evaluated rather than silently declaring completeness. Standard IMAP body/header search and optional attachment search must be distinguished.

The index is derived and rebuildable from encrypted source messages plus metadata. Corruption triggers an observable rebuild/error path and correct fallback where feasible, never silent partial results. Index-key rotation may rebuild rather than re-encrypt segments in place.

## Acceptance Checks

Run Lucene Directory contract tests and corruption/random-seek tests. Compare all advertised SEARCH predicates against a simple reference evaluator under index lag, rebuild, extraction failure, COPY/MOVE/EXPUNGE, and concurrent delivery. Benchmark indexing/search/cache behavior on representative mailboxes; whitepaper overhead estimates are not acceptance measurements.