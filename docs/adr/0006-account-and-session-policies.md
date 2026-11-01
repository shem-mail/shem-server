# ADR 0006: Account, Delivery, and Session Policies

Status: proposed.

| Topic | Policy | Rationale / exposure |
| --- | --- | --- |
| Mail before enrollment | Accepted by default (`delivery.acceptBeforeEnrollment`) | Sealed to the bootstrap key: an administrator who kept the bootstrap password and key files can read it. Keep bootstrap validity short (default 72 h). |
| Bootstrap credentials | Capability `ENROLL` only; no IMAP/SMTP access | Enrollment cannot be skipped. |
| Blocked / deletion-pending accounts | No authentication, no delivery; live leases revoked immediately | `MailboxRegistry` subscribes to identity changes. |
| Account recreation | New mailbox id, key, and UIDVALIDITY; waiting period (default 30 days) after deletion | Mitigates silent address takeover by administrators. |
| Quota while locked | In-memory ledger of on-disk ciphertext bytes, scanned per process; conservative reservation per delivery | No plaintext per-message ledger; sizes are already visible on disk. |
| Locked-user rules | Global receipt-time policy with symbolic targets (INBOX/Junk); private per-user rules deferred until unlock | Matches mail-policy.md default proposal. |
| App passwords | `ssss-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx`: public 4-char selector + 120 secret bits; capabilities MAIL_ACCESS and SUBMIT only | Selector and slot kind are visible in slot file names (not secret entropy). Primary passwords may not use this format. |
| Recovery codes | 160-bit, single use; using one replaces the password and ends all sessions | |
| Password change | Rewraps the master key; every other session of the mailbox ends (API, pending logins, IMAP, submission), the requesting one stays | Web sessions share the one password slot, so ending only "the old slot except the requester's" left other web sessions on that slot alive. App passwords stay valid, so mail clients reconnect. Old slots in backups still unwrap the same master key. |
| Rotation | New master/key/data root; app and recovery slots removed; every other session ends right after the keyring commit, before the resumable steps; requesting session stays | See ADR 0002. |
| Ending other sessions | Self-service `DELETE /api/v1/me/other-sessions` (step-up, `KEY_ADMINISTRATION`) ends every session of the mailbox except the caller's | Credentials are unchanged: to keep a mail client out, delete its app password; to keep a password holder out, change the password. |
| Slot revocation | Removes slot, ends leases derived from it; last password slot cannot be removed | Does not retract copied keys. |
| Multi-recipient SMTP | Per-recipient blobs; any failed accepted recipient yields a temporary failure for the transaction | Retries may duplicate already committed recipients (documented, not deduplicated by Message-ID). |
| Development bootstrap | `shem dev …` requires `dev.bootstrap.enabled=true` and non-production mode; holds the data-directory lock; prints the bootstrap password once | Uses the same provisioning/enrollment services; no key or plaintext access. |
