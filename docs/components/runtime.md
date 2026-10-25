# Runtime and Isolation

## Responsibility

Own composition, configuration, startup/shutdown, role supervision, resource budgets, and service-to-service contracts. One distribution does not mean one process with all permissions. See [plan](../../PLAN.md).

## Boundaries and Interactions

- Compose [inbound SMTP](smtp-inbound.md) and [policy](mail-policy.md) as a public-key-only role with [delivery](delivery.md) access, never mailbox private keys.
- Compose [IMAP](imap.md), [submission](smtp-submission.md), and [HTTP](http-api.md) with [session](sessions.md) capabilities in an authenticated role. The Phase 0 spike determines whether these share a process or use a narrowly scoped session broker.
- Isolate [outbound](outbound-delivery.md) queue access and [Tika](attachment-extraction.md) workers from unlocked mailbox secrets. [TLS](tls-certificates.md) distributes certificates without distributing mailbox keys.
- Enforce one metadata writer/coordinator per mailbox and explicit ownership of file handles, key leases, caches, and background jobs. Delivery while locked must not require the unlocked coordinator.

## Process Contract

Prefer local typed calls within a role and authenticated, bounded IPC between roles. Identity routing/public-key snapshots and encrypted delivery records can cross boundaries without plaintext mailbox content. Tika necessarily receives plaintext attachment streams; outbound delivery necessarily receives plaintext submitted mail. Optional scanners add further explicit exceptions.

The whitepaper's no-plaintext-socket ideal conflicts with separate process isolation. Resolve this in Phase 0: document peer authentication, OS permissions, backpressure, maximum frame size, disconnect behavior, and whether unnamed pipes or protected local sockets carry plaintext. No persistent IPC spools, core dumps, or transport tracing. Do not silently collapse roles or pretend IPC contains no plaintext.

## Persistence and Lifecycle

Typed versioned configuration contains no user password. Server-wide secrets live in service-account-only files. Role permissions separate public routing, encrypted mailbox files, outbound plaintext, and TLS/DKIM keys.

Startup validates supported formats, permissions, safe temp paths, and required sandboxing before opening listeners. Shutdown stops admission, drains bounded work, commits durable state, closes search/cache resources, and releases key leases. A deadline cancels remaining work without acknowledging undurable messages. Scheduled jobs must have explicit ownership and not retain an unlocked mailbox forever.

## Acceptance Checks

- A compromised inbound role cannot open private-slot material or inspect authenticated-role memory through normal OS permissions; document residual same-host/root threats.
- Clean restart and shutdown preserve acknowledged mail; unknown format versions and unsafe configuration fail closed.
- Saturating Argon2id, parser, indexing, or delivery queues stays within configured budgets and produces controlled protocol failures.
- James composition brings no default plaintext queue/store, and blocking callbacks never run on protocol event loops.