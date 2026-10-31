# Architecture Decision Records

Decisions required by [PLAN.md](../../PLAN.md#decisions-that-must-remain-explicit). Each record states the evidence actually gathered; "proposed" means it still needs the review named in the record.

| ADR | Decision | Status |
| --- | --- | --- |
| [0001](0001-java-baseline-and-build.md) | Java 25 target, JDK 21 validation in this environment, build gates | Accepted, JDK 25 run pending |
| [0002](0002-crypto-profile.md) | Crypto profile 1: Tink HPKE/streaming AEAD, key hierarchy, enrollment and rotation | Proposed (needs external review) |
| [0003](0003-argon2id-budget.md) | Argon2id parameters, global KDF budget, per-source limits | Proposed (VPS benchmark pending) |
| [0004](0004-metadata-store.md) | Own authenticated journal/snapshot segments instead of an embedded database | Accepted |
| [0005](0005-james-integration.md) | James spike findings: implement mailbox API directly, in-memory literals | Accepted for Phase 3 |
| [0006](0006-account-and-session-policies.md) | Locked-mailbox delivery, quota, bootstrap, app passwords, revocation policies | Proposed |
| [0007](0007-process-roles.md) | Process roles and IPC | Open |
| [0008](0008-search-index.md) | Encrypted Lucene trigram index as a conservative SEARCH filter | Accepted |
| [0009](0009-inbound-smtp.md) | Inbound SMTP on James protocol handlers with Shem hooks | Accepted |
| [0010](0010-mail-policy.md) | Inbound mail policy: SPF/DKIM/DMARC, greylisting, literal rules, attachment checks | Accepted (scores untuned) |
| [0011](0011-submission.md) | Authenticated submission (465/587); remote recipients via ADR 0012 | Accepted |
| [0012](0012-outbound-delivery.md) | Plaintext outbound queue, MX delivery, MTA-STS, DSNs, DKIM signing | Accepted (no DANE) |
| [0013](0013-http-api-sessions.md) | HTTP API: in-memory lease-backed sessions, self-service endpoints | Accepted (admin API in ADR 0016) |
| [0014](0014-mfa.md) | Mandatory second factor: TOTP and WebAuthn, stored in the sealed keyring | Accepted |
| [0015](0015-mail-client-credentials.md) | IMAP/SMTP accept only system-generated app passwords, never the main password | Accepted |
| [0016](0016-admin-api.md) | Independent admin credentials with mandatory TOTP; admin API without mail or key access | Accepted |
| [0017](0017-exports-jobs-openapi.md) | Streaming plaintext export, key rotation jobs, self-deletion, OpenAPI contract | Accepted (encrypted export open) |
| [0018](0018-acme-and-mta-sts.md) | ACME (acme4j, HTTP-01) with atomic generations, port-80 challenge/redirect listener, MTA-STS hosting | Accepted (no real-CA run yet) |
| [0019](0019-attachment-extraction.md) | Tika in isolation-probed worker processes; separate attachment index and search API with explicit coverage | Accepted |
| [0020](0020-audit-and-backup.md) | Hash-chained fail-closed audit log, offline backup/verify/restore, CI workflow | Accepted (no hot backup; CI not yet run) |
