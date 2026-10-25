# SMTP Submission

## Responsibility and Interfaces

Accept authenticated user mail on port 465 (implicit TLS) and 587 (STARTTLS required before AUTH). Reuse James SMTP modules with [sessions](sessions.md), [identity](identity.md), [delivery](delivery.md), [outbound delivery](outbound-delivery.md), and [TLS](tls-certificates.md).

## Sending Contract

1. Authenticate through the shared limiter/key-slot path and authorize the account, envelope sender, and allowed header identities/aliases. Do not permit sender impersonation or open relay.
2. Bound message size, recipients, send rate, memory, parsing, and queue admission. Reject header injection and malformed submission according to documented policy.
3. Canonicalize only as required and DKIM-sign the final transmitted bytes using the domain selector/key. Verify that no later mutation invalidates the signature. RSA-2048 is the initial compatibility candidate; a second Ed25519 signature needs explicit testing.
4. Route local recipients directly to encrypted delivery; remote recipients enter the separate plaintext outbound queue. An all-local message never uses that queue.
5. Return final success only after every accepted destination has durable responsibility recorded. Define mixed-local/remote partial commit behavior consistently with inbound SMTP retry ambiguity.

DKIM private keys are server-wide secrets, readable only to the signing role and not protected by a mailbox password. Manage selectors/rotation through authorized admin endpoints. Document that a leaked server-secret backup exposes domain signing capability but does not unlock mailboxes.

## Sent Copies

The Sent copy must be encrypted, but ordinary SMTP clients often create it themselves with IMAP APPEND. Specify a per-account/client policy rather than silently storing two copies. Proposal: standard submission leaves Sent filing to IMAP clients; any explicit server-managed Sent mode writes through encrypted delivery with a clear opt-in and documented idempotency limits. Never infer duplicates only from Message-ID.

## Persistence and Failures

No submission password or unlocked key is stored in the outbound queue. The queue must deliver after the submitting session ends. Transient storage/queue/DNS-dependent admission failures use appropriate temporary responses; account/sender authorization failures are permanent for the transaction. Do not acknowledge only an in-memory job.

## Acceptance Checks

Test AUTH-before-TLS rejection, revoked app slots, unauthorized aliases/header senders, DKIM verification of final queued bytes, local-only/mixed/external routing, queue failure, disconnect after commit, rate limits, and Sent-copy policies with real clients. Signing-key rotation must preserve in-flight item validity.