# ADR 0019: Isolated Attachment Extraction and Attachment Search

Status: accepted. Isolation is verified at startup by a probe. It is not a substitute for an operator-reviewed sandbox profile.

## Context

[attachment-extraction.md](../components/attachment-extraction.md) asks for bounded Tika extraction in a separate, underprivileged process with these properties:

- No network.
- No access to mailbox, key or queue files.
- Scratch space only on a private tmpfs.
- Limits on time, memory, size, depth and expansion.
- Startup fails, or extraction is disabled, when isolation cannot be met.

[search-index.md](../components/search-index.md) adds two requirements:

- Attachment search is distinct from standard IMAP search.
- An extraction failure can never count as coverage.

## Decision

### Worker processes (`shem-extract`)

- **Process and protocol:** Tika 4.1.0 runs in separate JVMs (`ExtractionWorker`). They talk to the parent over stdin/stdout with a framed, length-checked binary protocol (`Protocol`).
  - The worker keeps the real stdout for frames only. Library output goes to stderr, which the parent discards, so there are no worker logs.
  - The environment is cleared.
- **Parsers:** only the needed parser modules are on the classpath (PDF, Microsoft Office, misc office for RTF/ODF, text/CSV, HTML, mail). There are no image, OCR or external-tool parsers, and no archive parser beyond what Office formats embed. The Microsoft module also brings PST, Access and embedded-ZIP support; those formats are accepted but not separately tested.
- **What the worker receives:** decoded attachment bytes, the declared content type, and the file-name extension (at most 10 alphanumeric characters). It never receives the file name, keys, tokens or mailbox paths.
- **Limits** (configurable unless noted; defaults in parentheses):
  - Input: `extraction.maxInputBytes` (25 MiB). Read into memory by the parent; anything larger is "limit reached" without starting a worker.
  - Output: `extraction.maxOutputChars` (1,000,000). Text is returned with a truncated flag.
  - Wall-clock time: `extraction.timeout` (30 s). On expiry the worker is killed.
  - Heap: `extraction.heapMiB` (512); metaspace 128 MiB and direct memory 64 MiB are fixed.
  - One active processor and Serial GC; heap and core dumps off; attach and perf data off.
  - Embedded documents (fixed): depth at most 4, count at most 100.
  - Tika's `SecureContentHandler` defaults for compression ratio, plus POI's zip-bomb checks.
  - Workers: `extraction.workers` (2). Each is recycled after `extraction.requestsPerWorker` requests (100) or after any failure.
- **CPU and process limits:** CPU time and process-count limits belong in the sandbox wrapper (for example `prlimit` or systemd properties). The JVM cannot enforce them itself.
- **Scratch:** each worker gets its own `java.io.tmpdir` under `extraction.scratch`, deleted when the worker is destroyed. On pool start, everything under the scratch root is deleted, which covers runs ended by a hard kill. The server's shutdown hook now waits up to 30 seconds for cleanup.

### Isolation probe

- **The probe:** before first use, the parent starts a worker and asks it to:
  - connect to a loopback port the parent just opened;
  - read `data/.extraction-canary`, an owner-only file in the data directory;
  - report whether its temp directory is the expected scratch directory on tmpfs or ramfs (from `/proc/self/mounts`).

  A worker in its own network namespace cannot reach the host's loopback. A worker whose view of the data directory is masked cannot read the canary.
- **When isolation is required** (`extraction.requireIsolation=true`, the default and mandatory in production mode): any failing property aborts `serve` with a message naming what is missing.
- **In development mode,** isolation may be turned off; the server then logs a warning on every start.
- **Sandbox wrapper:** `extraction.sandbox` names one executable that runs its arguments (the worker JVM command) sandboxed. `docs/examples/extraction-sandbox.sh` uses `unshare --user --map-root-user --net --mount` and mounts an empty tmpfs over the data directory; the script includes a bubblewrap equivalent. Shem never changes host settings.
- **Limits of the probe:** it checks the properties the threat model names. It does not prove the absence of other channels (for example `/proc` of other processes or Unix sockets). A reviewed sandbox profile (bubblewrap, systemd or a container) remains the operator's responsibility.

### Attachment index (`shem-search`)

- **A separate extension:** `AttachmentIndex` uses its own directory, key purpose `attachment-index` and coverage, so standard IMAP `SEARCH` never depends on extraction.
- **What counts as an attachment:** every leaf part with `Content-Disposition: attachment`, and every leaf that is not an inline `text/plain` or `text/html` body. Embedded `message/rfc822` parts go whole to the mail parser.
- **Out of scope by design:** `image/*`, `audio/*` and `video/*` never reach a worker and do not make a message incomplete.
- **Per-message limit:** at most 32 attachments are processed.
- **Per-message result:** one encrypted document holding the trigrams of the whitespace-collapsed, case-folded text, and a status:
  - `complete`: every in-scope attachment was extracted fully, or there were none.
  - `incomplete`: an attachment was encrypted, truncated, over a limit or failed to parse, or the message could not be parsed.

  Text is never stored.
- **Unavailable extractor:** if no worker can run (not started, or shut down), the message gets no document and stays pending until `retry()` or the next unlock. It never becomes covered.
- **Matching:** trigram matching is a superset of phrase matching, because the text is not stored, so false positives are possible. There are no false negatives for text that was extracted. Queries need at least 3 characters.

### Attachment search API

`POST /api/v1/me/attachment-searches {query, allowIncomplete}` (full mailbox session):

- **Results:** at most 1000 `{folder, uidValidity, uid}` references for matches, plus every incompletely searched message, and `pending` and `complete` flags. Clients fetch the messages themselves over IMAP; there is no webmail.
- **Pending messages:** while any message is pending, the request fails with `409` unless `allowIncomplete=true`. A promised scope is never silently reported as complete.
- **Query placement:** the query is in the body, so search terms never appear in URLs.

## Consequences

- **Plaintext over IPC:** attachment plaintext crosses process boundaries through pipes. This is the documented process-isolation exception, not end-to-end encryption.
- **Size:** about 40 MB of parser dependencies (PDFBox, POI and others) ship in the distribution. Two annotation-only artifacts (`spotbugs-annotations`, `bnd.annotation`) are compile-time-only dependencies needed by `-Werror`.
- **Memory:** each in-flight attachment of up to 25 MiB is held in parent memory, so the bound is the number of workers times `maxInputBytes`.
- **Relock:** attachment search state survives relocking, because the index is encrypted under the mailbox data root and rebuilt after rotation.

## Evidence

- **`WorkerPoolIT`** (real worker JVMs):
  - Text, HTML, CSV, RTF, PDF, DOCX and embedded `.eml` are extracted.
  - An encrypted PDF gives `Encrypted`; PNG gives `Unsupported`; output truncation is reported; a 64 MiB-inflating DOCX is not returned as text; the input limit is enforced.
  - A stuck worker is killed at the timeout and its scratch deleted.
  - Stale scratch is wiped at start.
  - Required isolation refuses an unsandboxed worker, naming the missing properties.
  - Run as root, the reference sandbox (`unshare` network and mount namespaces, tmpfs over the data directory, scratch in `/dev/shm`) passes all three probe properties and still extracts a PDF.
- **`AttachmentIndexTest`** (fake extractor):
  - Coverage and completeness per message.
  - Encrypted and truncated attachments are incomplete; images are out of scope and never sent to a worker; only the extension is passed.
  - Whitespace- and case-insensitive phrase match; message bodies are not attachment text.
  - No plaintext markers on disk.
  - An unavailable extractor leaves messages pending (this test caught a bug where the walker had swallowed the signal), and they are covered after `retry()`.
  - Coverage survives relocking without re-extraction.
- **`HttpAttachmentSearchIT`:** references and incomplete lists are returned; queries under 3 characters get `400`; pending messages give `409` unless allowed; the endpoint needs a session.
- **`OpenApiContractIT`:** covers the new route.
- **`ShemConfigTest`:** validates the extraction configuration.
- **Packaged-jar smoke run** (production mode):
  - With the example wrapper, the log reports "attachment extraction isolated".
  - Without a wrapper, `serve` refuses with "network reachable; data directory readable".
  - After SIGTERM, workers are gone and scratch is empty.
- **Not done:** file and network activity has not been traced with a syscall tracer. Seccomp is not applied. The probe covers the named properties only.
