# Implementation Status

Last updated with inbound mail policy (plan step 11). "Validated" means an automated test in this repository exercises it; nothing here is production-ready (PLAN Phase 6 gate).

Build: `mvn -Djava.release=21 verify` passes on JDK 21 (see [ADR 0001](adr/0001-java-baseline-and-build.md); JDK 25 not yet run).

| Plan step | Module | State |
| --- | --- | --- |
| 1 Cryptography | `shem-crypto` | Implemented: profile 1, envelopes, streaming AEAD, slots, keyring, Argon2id admission. Tamper/truncation/reorder/substitution/wrong-key/nonce tests. |
| 2 Identity | `shem-identity` | Implemented: domains, accounts, lifecycle, aliases (cycle detection, local-only targets), sender authorization, public-key cutover, quota ledger. Admin credentials/MFA not yet. |
| 3 Message store | `shem-store` | Implemented: immutable encrypted blobs, range reads, temp sweep, GC support. |
| 4 Metadata store | `shem-store` | Implemented per [ADR 0004](adr/0004-metadata-store.md). |
| 5 Sessions | `shem-mailbox` | Implemented: shared authenticator, dummy KDF, per-source limiter, leases/child leases, revocation, registry. MFA (HTTP) pending. |
| 6 Delivery | `shem-delivery`, `shem-mailbox` | Implemented: locked delivery, receipts, idempotent import, enrollment, password/app/recovery slots, rotation with re-encryption, garbage collection. |
| — Runtime | `shem-app` | Typed config, data-directory lock, composition root, gated `dev` bootstrap command, `serve` (TLS + IMAP and/or inbound SMTP), packaged jar + SBOM. |
| 7 Listener TLS | `shem-tls` | Implemented: PEM loading/validation (key match, hosts, validity, chain links), atomic hot reload, file watcher. |
| 8 IMAP | `shem-imap` | Implemented per [ADR 0005](adr/0005-james-integration.md) with complete exact-evaluation SEARCH; validated with a real client (`ImapClientIT`). |
| 9 Search index | `shem-search` | Implemented per [ADR 0008](adr/0008-search-index.md): encrypted Lucene Directory, trigram candidate filter verified against exact evaluation, rebuild on corruption/rotation. No benchmarks yet. |
| 10 Inbound SMTP | `shem-smtp` | Implemented per [ADR 0009](adr/0009-inbound-smtp.md) with minimal policy: recipient validation, no relay, size limits, encrypted spool, `250` only after durable commit. No kill -9 or real-MTA interoperability tests yet. |
| 11 Mail policy | `shem-policy` | Implemented per [ADR 0010](adr/0010-mail-policy.md): SPF (jSPF), DKIM (jDKIM, streaming), DMARC evaluation, Authentication-Results, in-memory greylisting, reloadable literal rules with GTUBE, attachment checks, Junk routing. No scanner integrations, ARC, or DMARC reports; scores untuned. |
| 12–17 | — | Not started: submission, outbound, HTTP API, ACME, extraction, operations. |

Phase 2 exit gate evidence: `MailboxVerticalSliceTest` (locked delivery → enrollment → unlock → import → read → restart with stable UIDs; replay idempotency; rotation; plaintext-marker scan of the data directory), store fault-injection tests at blob/receipt/journal/manifest boundaries, and disk-full injection before publish. Not yet covered: concurrent delivery during rotation under load, kill -9 process tests (only in-process crash simulation), CI pipeline (no CI configuration exists yet).
