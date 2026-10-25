# Operations, Backup, and Recovery

## Responsibility

Provide safe deployment, diagnostics, audit, consistent backup/restore, maintenance jobs, upgrades, and incident procedures across [runtime](runtime.md), [identity](identity.md), [stores](metadata-store.md), and [keys](cryptography.md). Operations must not create a privileged mailbox-decryption path.

## Consistent Backups

Immutable files alone do not guarantee a complete backup. Capture a committed manifest that pins the metadata snapshot, sealed journal segments, referenced blobs/key envelopes, pending encrypted delivery receipts, and required encrypted key-slot versions. Seal/rotate active segments or use an explicit checkpoint barrier; simply omitting an active segment can lose acknowledged changes.

Coordinate delivery and mailbox writers when selecting a backup generation, pin files against GC, and publish the backup manifest only after every referenced object is copied and verified. A locked mailbox must be backup-able without decrypting it. Define cross-account scope and routing/key-version consistency; do not rely on timestamp-based file selection.

Mailbox backups contain ciphertext, but routing configuration and server-wide DKIM/TLS/ACME/admin secrets are not automatically protected by mailbox encryption. Encrypt and restrict their backups separately. The plaintext outbound queue needs an explicit include/exclude and restore-duplicate policy. Search indexes may be omitted if restore marks them for rebuild and SEARCH remains correct.

Restore into a fresh isolated host, verify object/manifests and compatible formats, recover routing/key generations, replay metadata/receipts, rebuild derived indexes, and test with user-held credentials. Restore does not recover a lost password without a valid app/recovery slot. Never publish services with partially restored identity/key state.

## Observability and Audit

Persist aggregate counts, timings, error codes, and resource saturation only. No addresses, subjects, body excerpts, raw Message-IDs, credentials, query terms, or SMTP/HTTP payloads in logs, traces, metric labels, or diagnostics. In-memory abuse and greylist state expires and is not backed up. Debugging requires synthetic/redacted data and explicit non-retention controls.

Account deletion/recreation, role changes, key-fingerprint changes, and domain administration need an integrity-protected minimal audit trail. Use opaque identity references, restrictive access/retention, and an independently controlled append-only sink or witness if detection of admin tampering is required. A hash chain on a disk controlled by the same administrator cannot prove absence of deletion. Document the audit timing/linkability leakage and its deliberate exception to mailbox privacy.

Notify a user-designated independent address before destructive identity reassignment according to the waiting policy; protect that address as account-private data, and resolve how notification works while locked without exposing it to inbound. Do not claim a local audit log can defeat root or prevent a malicious operator from changing running software.

## Deployment, Maintenance, and Incident Handling

Use separate non-root service users/permissions, restricted IPC, original-client-IP validation, firewall/DNS/reverse-DNS setup, protected or disabled swap, private size-limited tmpfs scratch, disabled core/heap dumps, and enforced Tika network/filesystem limits. Document development-versus-production platform differences and refuse unsafe fallback modes.

Track renewal failures, queue depth/age, disk space, storage integrity, index lag, KDF saturation, and sandbox failure without user-content labels. Apply dependency/security updates promptly; publish versioned artifacts and SBOMs. Version storage formats, checkpoint before migrations, test interrupted upgrades, and state when rollback requires restoring a matching backup.

Define retention and GC for orphan blobs, expired queue items, old snapshots/journals, revoked slots, and account deletion. Backups retain historical access; a stolen running session or copied key may require containment and content re-encryption, not just slot removal. No secure-erase guarantee for SSDs or remote snapshots.

## Acceptance Checks

Run backup/restore drills during concurrent delivery, mutation, rotation, and locked operation; include interrupted copies, missing blobs, corrupted manifests, old format versions, and omitted indexes. Prove acknowledged data survives supported recovery. Check file permissions, process capabilities, safe telemetry, renewal/queue alerts, delayed account recreation, and audit-sink failure behavior before production release.