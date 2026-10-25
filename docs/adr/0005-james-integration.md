# ADR 0005: Apache James Integration (Phase 0 Spike)

Status: accepted and implemented in `shem-imap` (Phase 3, exact-evaluation SEARCH).

## Spike findings (James 3.9.1 sources)

- `apache-james-mailbox-store` `StoreMessageManager.appendMessage` always copies the appended message to `Files.createTempFile("imap", ".msg")` in the system temp directory before parsing. **Plaintext on disk; disqualifies the store module as-is** (also `FileBufferedBodyFactory`).
- `james-server-protocols-imap4` `ImapRequestFrameDecoder` writes literals larger than `inMemorySizeLimit` to `Files.createTempFile("imap-literal", ".tmp")`. Setting `inMemorySizeLimit >= literalSizeLimit` keeps literals in memory; memory is then bounded by connection count × literal limit, so both must be configured together.
- IMAP processors depend only on mailbox-API interfaces (`MailboxManager`, `MessageManager`, `SubscriptionManager`, quota/rights interfaces) plus an `EventBus` for selected-mailbox notifications. `event-bus-in-vm` is in-memory.
- Footprint of `james-server-protocols-imap4` + mailbox API: netty 4.1, reactor-core, guava, commons-configuration2, vavr, fastutil, jutf7, mime4j (≈40 jars). `james-server-protocols-smtp` additionally pulls the mailet API, queue API, JWT/JAXB, reactor-netty-http; Shem will use `protocols-smtp` + `protocols-netty` hooks instead.

## Decision

Implement `MailboxManager`/`MessageManager` (and the small subscription/quota/rights interfaces) directly over `MailboxLease`, without `StoreMailboxManager`. Publish `Added`/`Expunged`/`FlagsUpdated` events to the in-VM event bus for every change, including receipt imports. Configure `inMemorySizeLimit = literalSizeLimit = message.maxBytes` and cap concurrent IMAP connections. Search starts with an exact evaluator over decrypted messages; Lucene is a later performance layer (PLAN step 9).

Authentication: the adapter's `authenticate` calls `SessionService` and stores the lease in the `MailboxSession`; SCRAM/CRAM mechanisms are not offered.

## Residual risk

A self-composed James stack is unsupported by the James project; interoperability must come from Shem's own transcript and real-client tests. Every James upgrade needs the temp-file inventory repeated (grep for `createTempFile`, `DeferredFileOutputStream`, `java.io.tmpdir`).

## Implementation notes (shem-imap)

- `ShemMailboxManager`/`ShemMessageManager` implement the mailbox API over `MailboxLease`; James's store module supplies only `SimpleMailboxMessage`, `MessageResultImpl`, `MessageSearches`, and `DefaultTextExtractor` over lazily decrypting content.
- **Third finding:** `MessageSearches` logs and *skips* messages whose evaluation throws, which would make SEARCH silently incomplete on a decryption failure. Shem tracks every content read during a search and fails the SEARCH if any read failed.
- `ShemLoginProcessor`/`ShemAuthenticateProcessor` replace James's LOGIN/AUTHENTICATE: PLAIN only (with SASL-IR), refused without TLS, client address passed to the shared limiter, authorization identity must equal the authentication identity, no user names in MDC.
- `ShemImapServer` (subclass of `IMAPServer`): TLS from the reloadable listener context, no JMX registration (connection descriptions expose user names), lease closed on channel inactivity (LOGOUT, disconnect, timeout).
- Metadata commits (from any writer, including receipt import) become in-VM `Added`/`Expunged`/`FlagsUpdated`/folder events, attributed to the originating session id, driving selected-mailbox state and IDLE.
- Library logging goes to `slf4j-nop`.
- Advertised: IMAP4rev1, AUTH=PLAIN, SASL-IR, LITERAL+, IDLE, MOVE, UIDPLUS, UNSELECT, ENABLE, NAMESPACE, CHILDREN, SPECIAL-USE, ID, APPENDLIMIT. Disabled until covered by tests: CONDSTORE, QRESYNC, OBJECTID, ESEARCH, SEARCHRES, WITHIN, LIST-EXTENDED, LIST-STATUS, LIST-MYRIGHTS, STATUS=SIZE, I18NLEVEL; ACL, QUOTA, METADATA, COMPRESS, REPLACE, XLIST processors are not installed.
- James's decoder validates a command against the session state when it is decoded, so a SELECT pipelined in the same packet as LOGIN is rejected; clients that wait for the LOGIN completion (as RFC 3501 clients do) are unaffected.

## Evidence

`ImapClientIT` (Jakarta Mail/Angus IMAP client over TLS): locked delivery then LOGIN, FETCH, implicit `\Seen` on `BODY[]`, STORE, SEARCH by flag/subject/body, CREATE, COPY, EXPUNGE, RENAME, APPEND, LIST; IDLE push of a delivery made while selected; wrong password; lease released and mailbox locked after logout; plaintext connection not served; capability list; and a `WatchService` on a dedicated `java.io.tmpdir` proving that a 2 MiB APPEND/FETCH creates no temp file (the same test fails with `imap-literal*.tmp` when `inMemorySizeLimit` is lowered to 64 KiB). Manual check of the packaged jar with `openssl s_client`.
