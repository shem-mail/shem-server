# ADR 0008: Encrypted Search Index

Status: accepted for Phase 4 (performance layer only; exact evaluation remains the correctness source).

## Context

[PLAN step 9](../../PLAN.md) and the [search component](../components/search-index.md) require an encrypted Lucene index that never makes IMAP SEARCH incomplete, including while indexing lags behind delivery, after corruption, and after key rotation. The exact evaluator from step 8 (James `MessageSearches` over decrypted content) already gives complete results.

## Decision

- **Index content:** a per-mailbox Lucene 10.5.2 index (`shem-search`), keyed by blob id, holds the character trigrams of exactly the text James's `MessageMatcher` scans for `BODY` (decoded bodies, preambles, epilogues) and `TEXT` (those plus raw header field bodies). Characters are upper-cased per character, as the matcher does.
  - Flags, folder membership, dates, and sizes are never indexed. They come from metadata at search time.
  - COPY/MOVE need no reindexing, because blob content is immutable.
- **Encrypted Directory:** `EncryptedDirectory` wraps `NIOFSDirectory`. Every file is Tink streaming AEAD (AES-256-GCM-HKDF, 16 KiB segments, seekable), and the associated data is the mailbox id plus the file name.
  - The key is derived from the mailbox's current data root, with a purpose label, through the mailbox extension API.
  - Lucene's commit rename re-encrypts the small `pending_segments_N` file under its destination name into a temporary file, then renames that atomically.
- **Query use is conservative:**
  - The index is consulted only for top-level `BODY`/`TEXT` criteria of three or more characters.
  - It can only *exclude* messages it covers that cannot match. Every remaining message, and every uncovered one, is evaluated exactly.
  - Coverage (the set of blob ids) is published together with the Lucene reader that contains it, as one `Snapshot`. A search never pairs a newer reader with older coverage, or the reverse.
- **Indexing:** asynchronous batches on a bounded platform-thread pool (CPU-bound work), committed before coverage grows.
  - Messages that cannot be indexed completely stay uncovered and are always evaluated exactly. That covers parse failure, an unsupported charset, more than 300,000 distinct trigrams, or a segment over 64M characters.
- **Failure handling:**
  - An authentication failure or corrupt index on unlock causes the index to be deleted and rebuilt from the mailbox.
  - A data-version marker that differs from the current data root has the same effect, which covers key rotation; the coordinator restarts extensions after re-encryption.
  - A search never fails because of the index; only failures of exact evaluation fail SEARCH.

## Finding

James's `MessageMatcher` carries its partial-match state across header fields and MIME parts, so a match can span a segment boundary (for example, the end of one part's text and the start of the next). Trigrams are therefore taken over each continuous stream the matcher reads, not per segment. Per-segment trigrams produced false negatives in the randomized test before this change.

## Residual leakage and risk

- File names, file sizes, and modification times in `searchindex/` are visible at rest. They reveal Lucene segment structure and the approximate index size and growth (roughly the number and size of indexed messages), not content.
- Lucene keeps decrypted index pages and terms in heap while the mailbox is unlocked. This is consistent with the zero-access-at-rest scope; JVM memory erasure is not claimed.
- Trigram filtering is weaker for very short or very common substrings, so those fall back to near-full exact evaluation. Correctness is unaffected; benchmarks are pending.

## Evidence

- `EncryptedDirectoryTest`: random access, clones, and slices; Lucene checksums over plaintext; tampering, truncation, and file swapping detected; wrong key; rename re-encryption; full index lifecycle with no plaintext terms on disk.
- `SearchIndexTest`:
  - Randomized MIME corpus: no false negatives against `MessageMatcher` for random substrings, including ones spanning part and header boundaries.
  - Coverage after import.
  - Rebuild after a corrupted `segments_N`.
  - Rebuild under the new data root after rotation.
  - Plaintext-marker scan.
- `ImapClientIT.indexedSearchEqualsExactEvaluationDuringAndAfterIndexing`: IMAP SEARCH results are identical while indexing is in progress and after it completes.
- The Java vector incubator module is not enabled. Lucene falls back to scalar code, which only affects performance.
