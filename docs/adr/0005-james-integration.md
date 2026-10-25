# ADR 0005: Apache James Integration (Phase 0 Spike)

Status: accepted as the Phase 3 approach; the adapter itself is not yet implemented.

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
