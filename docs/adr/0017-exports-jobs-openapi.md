# ADR 0017: Streaming Export, Key Rotation Jobs, Self-Deletion, and the OpenAPI Contract

Status: accepted. Encrypted exports are still open (see below).

## Context

[http-api.md](../components/http-api.md) requires:

- A bounded, streaming export with no plaintext spool. Encrypted exports need a user-controlled destination key; plaintext exports are a deliberate authenticated download over TLS.
- Resumable rotation jobs that pause safely when their lease ends and that never persist credentials.
- Self-service delayed deletion.
- A machine-readable OpenAPI contract with contract tests.

## Decision

### Export: `POST /api/v1/me/exports` then `GET /api/v1/me/exports/{id}/content`

- **Negotiation:** `POST` needs `MAIL_ACCESS` and step-up, and takes `{format}`. It returns a ticket that only the same session can redeem, once, within 5 minutes. The ticket is not a credential: the session is still required, and no token ever appears in a URL.
- **Format `shem-mbox-zip-v1`** (`MailboxExport`, in `shem-mailbox`), a ZIP stream:
  - `folders/N.mbox`: mboxrd, one file per folder, in UID order.
  - `manifest.json`, written last: folder names, special use, UIDVALIDITY, and per message its UID, flags, keywords and internal date.

  Details:
  - Message bytes are unchanged apart from `>From ` quoting, so CRLF line endings are kept. The `From ` separator line and the blank line after each message use LF.
  - Entries are named by index, so folder names never become paths and path traversal is impossible.
- **No staging:**
  - Messages are decrypted, quoted and compressed straight into the HTTP response. Memory is one folder's UID list plus the manifest, a few dozen bytes per message.
  - Each message is re-read by key: messages expunged during the export are skipped, and the metadata read lock is never held while writing.
- **Lease:** the export runs on a child lease of the session.
- **Aborting:** if the client disconnects, the session ends, or the mailbox is locked mid-stream, the server drops the connection instead of finishing the chunked body.
  - A partial export is therefore a transport error for the client, never a cleanly ended but truncated download.
  - The ZIP also lacks its central directory.
- **Limits:** at most 2 exports run at once server-wide (`429` beyond that).
- **Encrypted exports are not implemented:** `format` accepts only `shem-mbox-zip-v1`. Adding one needs a reviewed recipient-key format (for example age or OpenPGP) and remains open rather than being improvised.

### Key rotation jobs: `POST /api/v1/me/key-rotations` and `GET /api/v1/jobs/{id}`

- **Starting:**
  - The request always re-proves the current password; a recent login is not enough. Rotation needs the password to wrap the new master key.
  - It needs a full session (`KEY_ADMINISTRATION` and `MAIL_ACCESS`).
  - It returns `202` with `Location: /api/v1/jobs/{id}`.
- **Idempotency:** `Idempotency-Key` is bound to the mailbox, so the same key returns the same job. At most one rotation runs per mailbox (`409`).
- **Running:**
  - `KeyLifecycle.rotateKeys` runs on a child lease, on a bounded pool (2 running, 8 queued). The password lives only in the running task.
  - The keyring commit is atomic. Anything interrupted afterwards (public-key cutover, metadata re-encryption, key retirement) is finished by `KeyLifecycle.resume` at the mailbox's next unlock. Nothing extra is persisted to make rotation resumable.
- **Status:** the job record holds `running`, `succeeded`, `failed` or `interrupted` with a sanitized detail.
  - If the session ends mid-run, the job reports `interrupted` ("completes at the next login").
  - Records are in memory, kept for 1 hour after finishing, at most 256.
- **Visibility:** only the owning mailbox can see a job. Another user, or an unknown id, gets the same `404`.
- **Effect:** rotation removes app passwords and the recovery code, and ends their sessions, as before. The requesting session stays open.

### Self-deletion: `DELETE /api/v1/me`

- It needs a full session (not a recovery session) and step-up; `currentPassword` may be sent in the body.
- It moves the account to `deletion_pending`, which ends every session and stops delivery, and returns a note that backups and earlier copies are not erased.
- Final erasure and recreation follow the account lifecycle of [ADR 0006](0006-account-and-session-policies.md).

### OpenAPI contract

- `shem-http/src/main/resources/org/shem/http/openapi.json` (OpenAPI 3.0.3) is served at `GET /api/v1/openapi.json`.
- **Covered:** every route, including the admin routes from [ADR 0016](0016-admin-api.md).
- **`x-shem-principal`:** each operation carries `public`, `mailbox` or `admin` to name who may call it.
- **Versioning:** `info.version` versions the contract; breaking changes need `/api/v2`.
- **Contract tests (`OpenApiContractIT`):**
  - The served document is the packaged one.
  - Every documented operation is routed; non-public ones answer `401` anonymously.
  - Every undocumented method on a documented path answers `405`.
  - A mailbox session gets `401` on every admin operation, and an admin session gets `401` on every mailbox operation.

## Consequences

- **Plaintext download:** a plaintext export is the user's mail in the clear on their device. It is deliberate, authenticated, fresh and single-use, but it is the user's choice to protect the file.
- **Restarts:** a server restart forgets job records. An interrupted rotation still completes at the next unlock, but its status can no longer be queried.
- **Deletion:** delayed deletion cannot be cancelled from the API yet. An administrator can set the account back to `active` during the waiting period.

## Evidence

- `MailboxExportTest`:
  - Folder and manifest content, including JSON escaping of folder names and keywords.
  - mboxrd quoting, which is independent of buffer boundaries (byte-at-a-time input gives identical output).
  - A revoked lease stops the export.
- `HttpExportAndJobsIT`:
  - The export is bound to the session, single-use, and returns a valid ZIP with `no-store`.
  - Ticket expiry and step-up.
  - Revoking the mailbox mid-stream gives the client an `IOException`. This test fails if the server finishes the response normally (checked by mutating the code).
  - The rotation job: password required, `202` plus `Location`, `succeeded`, new public key, idempotency, session survives, other users get `404`.
  - A rotation interrupted by logout still leaves the mailbox usable at the next unlock.
  - Self-deletion: refused for recovery sessions and without step-up; the account becomes `deletion_pending` and its sessions end.
- `OpenApiContractIT`: as listed above.
