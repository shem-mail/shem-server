# Outbound Queue and Delivery

## Responsibility

Deliver remote mail accepted by [submission](smtp-submission.md) without depending on an unlocked user. Own a durable retry queue, per-recipient state, DNS/MX routing, transport-security policy, and delivery-status notifications. Send local DSNs through [encrypted delivery](delivery.md).

## Explicit Security Exception

Queued message content, envelope recipients, and delivery state are readable on disk. This is the whitepaper's deliberate exception and remains exposed in snapshots/backups. Keep the queue physically/permission-separated from encrypted mailbox storage, service-account-only, and inaccessible to the public inbound role. Do not claim whole-server zero-access encryption.

The queue contains no user password, mailbox private key, or persistent unlock token. Use no general-purpose broker that introduces another undocumented plaintext copy. Backups and diagnostics must distinguish queue data from naturally encrypted mailbox data.

## Queue and Transport Contract

- Publish complete signed message bytes and recipient state atomically with durable acknowledgement. Use opaque queue IDs and bounded capacity; reject admission temporarily when full.
- Resolve MX (including null MX), follow RFC-compatible fallback, distinguish transient/permanent DNS/SMTP failures, and apply bounded connection/rate/time budgets.
- Retry per destination/recipient with documented backoff and maximum lifetime; record attempts without retaining unrestricted SMTP transcripts. Do not resend to recipients already durably marked delivered except unavoidable remote-ack ambiguity after crashes.
- Offer STARTTLS and enforce valid cached MTA-STS policies. DANE requires DNSSEC-validated TLSA evidence; absence of validation is not DANE assurance. Fail/retry rather than downgrade when an enforced policy cannot be met.
- Cache DNS/MTA-STS policy with bounded retention; treat recipient-domain routing metadata as sensitive operational data. Fetch policies with SSRF-safe network handling and no message content disclosure.
- Generate RFC-compatible DSNs after final failure/expiry, use a null reverse path where required, suppress bounce loops, and do not bounce rejected unauthenticated inbound spam. Bound returned original content.

Delete completed/expired queue items promptly, including temp and state files; secure erase on SSDs is not guaranteed. Keep aggregate metrics, not permanent per-message delivery history. Remote acceptance does not guarantee inbox placement or end-to-end confidentiality.

## Acceptance Checks

Use controllable SMTP/DNS/TLS peers for MX ordering, null MX, 4xx/5xx, partial recipients, disconnects, retries, expiry, DSNs, certificate failure, MTA-STS downgrade attempts, and validated/invalid DANE. Restart at queue state transitions and verify responsibility is not lost. Demonstrate delivery after user logout without access to mailbox keys.