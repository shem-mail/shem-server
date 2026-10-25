# Isolated Attachment Extraction

## Responsibility and Interfaces

Extract bounded text from attachments for [search](search-index.md) using Apache Tika in a separate underprivileged process. This is neither a mail delivery requirement nor a full antivirus service. [Mail policy](mail-policy.md) owns receipt-time safety decisions.

The parent sends a bounded plaintext attachment stream and non-sensitive parser hints through controlled IPC. The worker returns bounded text plus structured status: success, unsupported/encrypted format, limit reached, or parser failure. It never receives mailbox private keys, wrapping keys, session tokens, or mailbox storage paths.

## Supported Work and Limits

Initial candidates: PDF, Office/OpenDocument, RTF, text, HTML, CSV, and embedded email through maintained Tika parsers. Confirm actual formats with the pinned dependency set. Password-protected files are not decrypted; OCR/Tesseract is out of scope.

Enforce wall-clock and CPU time, heap/process memory, input bytes, output characters, archive expansion ratio/bytes, nesting depth, child-process count, and concurrent worker limits. Stop consuming on cancellation and terminate stuck workers; reset/recycle workers after failures.

## Isolation and Temporary Data

No network, no privilege escalation, minimal read-only runtime files, no access to key/queue/mailbox directories. Apply OS-level sandbox/service/container restrictions; JVM process separation or a ForkParser setting alone does not enforce these properties. Validate the chosen deployment mechanism in Phase 0.

Parsers may spill to files even with stream input. Direct all scratch directories to a private size-limited tmpfs/RAM-backed location, disable core dumps, require protected/disabled swap, and remove scratch on success, failure, and worker restart. If required isolation/temp guarantees cannot be met, disable extraction or fail startup according to configuration; do not silently use the system temp directory. macOS development requires an explicit equivalent or a Linux test environment.

Text returns only to the in-memory indexer; no plaintext extraction cache, worker logs, or stored Lucene text field. IPC plaintext is an explicit process-isolation exception, not a claim of end-to-end encryption.

## Acceptance Checks

Trace file/network activity for PDF/Office/embedded archives, malformed and encrypted documents, and decompression bombs. Verify timeout/kill/cancellation, output truncation status, tmpfs limits, worker cleanup, and denial of access to mailbox/key paths. Indexing must not mark extraction failures as complete attachment coverage.