# IMAP Adapter

## Responsibility and Interactions

Expose standard mail access on implicit-TLS port 993 using Apache James protocol/mailbox modules in Shem's own runtime. Implement the required James mailbox contracts over [metadata](metadata-store.md), [message storage](message-store.md), and [search](search-index.md). [Sessions](sessions.md) owns authentication/unlocking and [TLS](tls-certificates.md) owns transport credentials.

## Protocol Contract

- Do not allow credentials before TLS. Pass unlock-capable authentication to the shared session service; avoid storing passwords in protocol session attributes longer than necessary.
- After login, import pending [delivery receipts](delivery.md) through the mailbox coordinator. More incoming receipts during the session trigger bounded replay and client updates.
- Implement folder listing/creation/rename/deletion, subscriptions, SELECT/EXAMINE, FETCH, flags, APPEND, UID SEARCH, COPY, MOVE where supported, EXPUNGE, and IDLE using the chosen James contracts.
- Advertise only tested capabilities. UIDPLUS, CONDSTORE, QRESYNC, and extensions require matching persisted state and interoperability coverage, not simply library availability.
- Keep stable UIDs and UIDVALIDITY, allocate destination UIDs for COPY/MOVE, and distinguish sequence numbers from UIDs. Flags and folder predicates query metadata, not stale Lucene fields.

FETCH uses encrypted precomputed envelope/bodystructure and bounded blob range/decrypt streams; it must not materialize whole large mailboxes. APPEND uses the same encryption/durability rules as delivery, with authorized folder metadata handled under the unlock lease. No James cache or event subsystem may persist readable headers or flags.

SEARCH must remain complete before indexing catches up. Apply the [search contract](search-index.md), including exact semantics and index-lag fallback; do not return silently incomplete UID sets.

## Failure and Session Behavior

Map resource exhaustion, corruption, account blocking, and revocation to safe protocol failures without revealing data or treating damaged state as an empty mailbox. IMAP commands must not succeed before required metadata/blob commits. Multiple clients share the mailbox coordinator while retaining distinct principals and view/notification state.

LOGOUT, timeout, authentication failure, network disconnect, and server shutdown all release leases. IDLE sessions remain active only within configured idle/resource limits; aborted FETCH/SEARCH tasks promptly release child leases and buffers.

## Acceptance Checks

First prove standalone James integration in Phase 0. Reuse James MPT tests where practical, then run transcript and real-client tests for UID behavior, concurrent clients, IDLE, large APPEND/FETCH, folder operations, search under backlog, disconnects, and slot revocation. Inspect adapter dependencies for plaintext caches/temp files and default persistence paths.