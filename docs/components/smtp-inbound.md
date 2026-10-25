# Inbound SMTP

## Responsibility and Interfaces

Adapt Apache James SMTP modules for server-to-server reception on port 25. Use [identity](identity.md) for recipients, [policy](mail-policy.md) for checks, [delivery](delivery.md) for persistence, and [TLS](tls-certificates.md) for opportunistic STARTTLS. The inbound role never unlocks a mailbox.

## Transaction Contract

1. Bound connection count, time, command/header size, message size, recipients, and parsing work. Reject relay attempts and unknown/disabled recipients using configured anti-enumeration policy.
2. Apply greylisting and connection/envelope policy at appropriate SMTP stages. Gather SPF, DKIM, DMARC, spam, and attachment-safety results before final acceptance.
3. Stream DATA through bounded processing. Use encrypted provisional files when replay/random access is necessary; keep their ephemeral keys only in memory. No persistent plaintext spool, even when a library exceeds a memory threshold.
4. Pass the final canonical message, authenticated-policy results, recipient routing, and encrypted delivery instructions to the delivery service. Preserve original message semantics when inserting Authentication-Results.
5. Send final `250` only after durable blob and encrypted receipt commits for every accepted local recipient. Reserve quota before committing; no success based only on buffering or scheduling.

Filtering may finish only after the full message is available. Provisional ciphertext is not delivery acceptance; rejection or a crash must leave reclaimable ciphertext, not readable scratch data. Define how the final message is produced when inserted headers affect signing/verification and encryption.

## Failures and Persistence

Unknown routes and policy rejection use appropriate permanent responses; greylisting, unavailable storage, exhausted resources, and disk-full errors generally use temporary responses. Never return success after a failed durable write.

SMTP has a single final DATA response for accepted recipients. If some recipients commit before a later failure, a retry may duplicate their deliveries. Use internal transaction IDs for replay idempotency, document this limitation, and do not deduplicate solely by Message-ID or body hash. Disconnect after commit but before the client receives `250` has the same unavoidable ambiguity.

Persist only encrypted provisional data, blobs, and receipts through owning services. Counters/greylisting remain in memory; logs contain reason codes and aggregates, not envelope addresses or message identifiers.

## Acceptance Checks

Run James protocol tests where reusable and black-box SMTP tests for STARTTLS, pipelining, malformed DATA, size limits, multiple recipients, no open relay, source-IP handling, rejection after filtering, disk failure, and disconnect ambiguity. Kill the process around durability barriers and prove every acknowledged recipient can recover the message while still locked.