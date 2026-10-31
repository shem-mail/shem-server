# ADR 0020: Audit Trail, Offline Backup and Restore, and CI

Status: accepted.
- Online (hot) backup is not implemented.
- The CI workflow has not run yet.
- The audit log has no off-host witness beyond the stdout mirror.

## Context

[operations.md](../components/operations.md) asks for three things:

- **Audit:** an integrity-protected, minimal audit trail of identity and administration changes, with opaque references and an independent sink where tampering must be detected.
- **Backups:** consistent backups pinned by a committed manifest, verified before publication, restorable into a fresh host without decrypting locked mailboxes.
- **Restore drills:** drills that include damaged backups.

AGENTS.md asks for CI with a pinned JDK and build environment, dependency and secret scanning, an SBOM and a versioned distribution.

## Decision

### Audit trail (`AuditLog`)

- **Format:** `data/audit/audit.log`, owner-only, one line per record:

  ```
  v1 seq time actor action target outcome prev hash
  ```

  `hash` is the SHA-256 of the line up to `prev`, and `prev` is the previous line's hash.
- **Fields:** restricted to the token alphabet `[A-Za-z0-9:._@-]`. Anything else is written as `invalid`, so no address, subject, credential or free text can enter a record. Targets are opaque domain, mailbox and alias ids.
- **Durability:** every append is fsynced.
- **Opening:** the whole chain is verified on open. A torn final line (no newline) is a write that never completed, and is cut off. Any other inconsistency (edited, reordered or missing records) refuses startup.
- **What is recorded:**
  - Every authenticated admin API mutation, audited at the routing layer: a durable `attempt` record before the change and `ok` or `failed` after. Creations carry the new id. If the attempt cannot be written, the change is refused with `503` (fail closed).
  - Admin password and TOTP results.
  - `shem admin create|delete`, backups and restores (actor `cli`).
  - Account key-fingerprint and lifecycle-state changes, whoever caused them (actor `system`, opaque mailbox id).
- **Limits:**
  - The chain detects modification inside the file, but not truncation of its tail or replacement of the whole file by whoever controls the disk.
  - `audit.stdout=true` mirrors each record to stdout for an independently controlled, off-host collector. Shem does not ship such a collector.
  - Records reveal when administrative events happened and which opaque objects they touched. This is the documented exception to mailbox-metadata privacy.
  - Retention and rotation are manual.

### Backup and restore (`Backup`, `shem backup …`, `shem restore`)

- **Offline only:** `backup create` takes the data-directory lock, so the server is stopped. With no writer running, every acknowledged object (blobs, receipts, metadata journal and snapshots, key slots, keyrings, routing) is on disk. The copy is consistent by construction, and locked mailboxes are backed up as ciphertext.
- **Not copied:**
  - Derived data: the search and attachment indexes, which rebuild at the next unlock.
  - Transient data: the inbound spool (no acknowledged mail lives there), the lock, temp files and the extraction canary.
  - The plaintext outbound queue, unless `--include-queue` is given (it prints a warning). After restoring a queue, items may be delivered twice; a duplicate is preferred to a loss.
  - Server secrets (`dkim/`, `acme/`, `admin/`), when `--exclude-secrets` is given. They are included by default, with a warning, so that a restore is complete.
- **Manifest:** `MANIFEST` is written last. It holds the format version, the scope flags, and `sha256 size path` per file, sorted, closed by a hash over the manifest. Every file is copied owner-only and fsynced before the manifest exists, so a backup without a manifest is incomplete by definition.
- **Verification:** `backup verify` and `restore` check the manifest hash and every file's size and hash, and reject missing, altered and unlisted files and unknown format versions.
- **Restore:**
  - The target must be absent or empty, and the backup is verified first.
  - Files are copied into `<target>.restore-staging`, re-hashed and then atomically renamed into place. A crash leaves the target absent; a leftover staging directory is removed by the next restore.
  - Users then sign in with their own credentials; nothing in a restore recovers a password.
- **Not implemented:** online backup with a checkpoint barrier across running mailbox writers and delivery. It needs coordination with `MetadataStore` journal sealing and with delivery admission. Until then the documented procedure is to stop the server.

### CI (`.github/workflows/ci.yml`)

- **Builds:** `mvn verify` (Java 21 target, ADR 0001) on JDK 21 and JDK 25, with Maven 3.9.11 downloaded and checked against its published SHA-512. This runs formatting, Error Prone/NullAway, unit and integration tests, dependency convergence and the SBOM.
- **Distribution:** a tarball named by commit SHA (jar, `lib/`, CycloneDX SBOM) is uploaded as an artifact.
- **Secret scan:** gitleaks over the full history.
- **Dependency scan:** osv-scanner over the SBOM.
- **Pinning:** actions and scanner images are pinned by version tag. Pinning them to full commit SHAs and digests is an open task, since it needs verified SHAs.
- **Dockerfile:** fixed to build the whole multi-module project; it previously copied only `shem-app` and could not build. The tmpfs/namespace sandbox test skips where namespaces are not permitted (for example `docker build`).

## Consequences

- **Backups need downtime.** For small installations this is acceptable; online backup remains a PLAN Phase 6 item.
- **Fail-closed audit:** a broken audit chain stops the server until an operator investigates. Availability is traded for tamper visibility, and the error message says what is wrong.
- **Runbook:** [operations-runbook.md](../operations-runbook.md) collects deployment, backup, restore and upgrade steps.

## Evidence

- **`AuditLogTest`:** chaining across reopen and the stdout mirror; owner-only permissions; free text replaced by `invalid`; a deleted record and an edited record detected; a torn final write cut off.
- **`HttpAdminIT`:** password, TOTP and mutation records, with the created id, contain no domain name and form a valid chain. With the audit log unwritable, a change is refused with `503` and does not happen.
- **`BackupRestoreTest`:**
  - **Backup:** derived data, spool and lock are excluded and secrets included. No plaintext markers appear anywhere in the backup.
  - **Restore into a fresh directory:**
    - The user signs in with their own password.
    - The appended message and the delivery that was still a pending encrypted receipt are both readable.
    - The search index rebuilds to full coverage.
    - The admin is restored, and a wrong password is refused.
  - **Damage:** altered, missing and unlisted files and a modified or missing manifest are detected, and an invalid backup leaves the target absent.
  - **Edge cases:** a non-empty target is refused, a leftover staging directory from a crash is removed, and `--exclude-secrets` is honored.
- **Not run:** the CI workflow and the Docker build. No Docker daemon was available here, and the workflow only runs on GitHub.
