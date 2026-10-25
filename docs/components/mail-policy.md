# Mail Policy and Filtering

## Responsibility and Interactions

Evaluate bounded in-memory mail policy for [inbound](smtp-inbound.md); supply encrypted delivery instructions to [delivery](delivery.md). Reuse maintained SPF/DKIM/MIME libraries, not handwritten protocol or signature implementations.

## Policy Pipeline

- Greylist by sending IP, envelope sender, and recipient using bounded in-memory TTL records only. Restart loss is acceptable. Never persist address tuples.
- Validate SPF, DKIM, and DMARC with bounded DNS resolution and a deliberate temporary-DNS-failure policy. Optional ARC is a later capability, not an advertised default.
- Insert trustworthy Authentication-Results before encryption; distinguish/remove untrusted headers claiming the local authentication authority.
- Apply protocol/IP-reputation checks without sending message content to third parties. Bound DNS fanout/cache lifetimes and document resolver-visible metadata.
- Run a small reloadable, non-learning rule engine over headers/body. Validate rule updates, constrain regex complexity/execution, and atomically replace a last-known-good ruleset. Spam content scores tag/reroute to Junk; they do not reject messages.
- Perform baseline dangerous-attachment checks: executable/script types, double extensions, and macros where a verified parser supports detection. This is not a full antivirus guarantee. Malware handling (tag/quarantine/reject) is a separate explicit policy.

## Locked-Mailbox Rules

Private user rules encrypted under mailbox keys cannot run while the mailbox is locked. Do not silently store them in plaintext or give inbound the user's private key. Phase 0 must choose between global receipt-time rules with encrypted symbolic targets, a deliberately exposed restricted receipt-time policy, or deferred user rules after unlock. Default proposal: global policy at receipt, private per-user rules deferred; communicate any resulting difference from immediate Sieve behavior.

Use symbolic destinations such as Inbox/Junk or opaque folder IDs in delivery instructions. Private folder names resolve only after unlock. A Sieve adapter is optional until the supported subset and storage model are specified.

## Optional Integrations and Persistence

SpamAssassin/Rspamd and clamd are opt-in exceptions to the single-package/no-plaintext-IPC ideal. Stream via protected local IPC; disable learning, content retention, body-derived remote lookups/hashes, debug mail dumps, and plaintext temp files. Specify timeouts, backpressure, failure policy, and isolation. No optional service becomes a mandatory runtime dependency.

Persist only public/global rules and configuration; persist per-message results only inside encrypted messages/receipts. No learned content database. Ruleset provenance and update integrity need checks; borrowed SpamAssassin scores are not automatically valid for a partial engine.

## Acceptance Checks

Use SPF/DKIM/DMARC fixtures, GTUBE, safe synthetic attachment/macro fixtures, malicious regex/archive cases, DNS failures, and scanner timeouts. Verify spam tagging versus malware rejection, atomic rules reload, locked-user behavior, and absence of persistent envelope tuples or content models.