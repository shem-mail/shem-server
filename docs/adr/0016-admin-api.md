# ADR 0016: Administrator Authentication and the Admin API

Status: accepted for domains, accounts, aliases, and DKIM. Admin factor rotation over HTTP, audit records ([operations](../components/operations.md)), and the OpenAPI contract are still open.

## Context

[identity.md](../components/identity.md) requires administrators to authenticate independently of any mailbox, with mandatory MFA, and without gaining any route to mailbox keys or plaintext. [http-api.md](../components/http-api.md) lists the admin routes and says an administrator bootstrap procedure belongs to operational provisioning.

## Decision

### Administrator credentials (`AdminStore`, `shem-identity`)

- **Storage:** `data/admin/admins.bin`, format `SHAD` version 1, written atomically and owner-only.
  - Each administrator has a key slot: the same Argon2id + AEAD construction as mailbox slots, with the server's slot parameters. The slot wraps a random per-admin key.
  - That key seals the administrator's TOTP secret, bound to the purpose `admin-factor`.
  - No separate password-verification hash exists: a password is correct exactly when the slot opens.
- **Unknown names:** they pay the same KDF cost (a dummy slot) and get the same failure.
- **Limits:** names match `[a-z0-9][a-z0-9._-]{0,31}`; passwords need at least 14 characters; at most 32 administrators.
- **Replay protection:** the last accepted TOTP step is persisted, so a code cannot be replayed after a restart.
- **No mailbox key:** administrators are not mailboxes and the admin key never wraps mailbox material.

### Provisioning: `shem admin create|list|delete NAME`

- It runs offline and holds the data-directory lock, so it never runs beside a server.
- `create` reads the password twice without echo, and prints the TOTP secret (base32 plus an `otpauth://` URI) once.
- It is allowed in production mode. Running it requires shell access to the data directory, which already implies control of the server.
- [ADR 0021](0021-first-run-bootstrap.md) adds a second way to create the *first* administrator: `serve` creates it on a fresh data directory, and it must replace its initial password and enroll TOTP at first login.
- **Recovering a lost admin factor:** delete and recreate the administrator. This gains nothing over mailboxes.

### Sessions (`AdminSessionStore`)

- **Separate from mailbox sessions:**
  - Cookie `__Host-shem-admin` or a bearer token. A mailbox session token is never an admin token, and the reverse.
  - Only the token fingerprint is stored.
  - Mailbox and admin sessions share no state.
- **Login has two steps:**
  1. `POST /api/v1/admin/auth/login {name, password}` returns a pending challenge, never a session.
  2. `POST /api/v1/admin/auth/mfa/verify {challenge, totp}` creates the session.

  The admin key is closed as soon as TOTP succeeds; the session holds no key material.
- **Lifetimes:** idle 15 minutes, absolute 8 hours. These are tighter than mailbox sessions because admin sessions need no unlocked key to amortize.
- **Limits:**
  - At most 64 sessions.
  - A challenge allows 5 attempts and lasts 5 minutes.
  - A source address is blocked after 10 failures in 15 minutes.
- **Request checks:** the same CSRF header, Origin and `Sec-Fetch-Site` checks as the mailbox API apply.
- **Step-up:** deleting a domain, rotating DKIM, and deleting an account (or `PATCH state=deletion_pending`) need a login within the last 5 minutes.

### Routes (`/api/v1/admin`)

Optimistic concurrency: `PATCH` carries `version`, and `DELETE` requires `If-Match: "<version>"`. A missing version gives `428`; a stale one gives `412`.

| Route | Behavior |
| --- | --- |
| `GET, POST /domains`; `GET, DELETE /domains/{id}` | Deleting refuses while accounts or aliases use the domain (`409`). |
| `POST /domains/{id}/dkim-rotations {selector}` | Generates a new RSA-2048 key for a new selector and switches signing to it. An existing selector is never overwritten (`409`). Returns the TXT record. |
| `GET /domains/{id}/dns` | MX, SPF, DMARC and the active DKIM TXT record. Public data only; never the private key. |
| `GET, POST /accounts`; `GET, PATCH, DELETE /accounts/{id}` | See the account notes below. |
| `GET, POST /aliases`; `PATCH, DELETE /aliases/{id}` | Loop validation lives in `IdentityService`. Senders are given as existing account addresses. |

Account notes:

- `POST` returns the one-time bootstrap password, which is never shown again.
- `PATCH` changes the quota or the state (`active`, `blocked`, `deletion_pending`).
- `DELETE` starts delayed deletion (`deletion_pending`); nothing is erased by the request.
- Blocking or deletion locks the mailbox and ends its sessions. `MailboxRegistry` observes the state change, so the HTTP layer does not do it.

No admin route reads, exports, or searches mail. None touches slots, keys or factors of a mailbox, and none resets a mailbox password. `HttpAdminIT` asserts that such paths return `404`.

### Deviation from http-api.md

The component table puts admin login on the shared `POST /api/v1/auth/login`. Admin login lives at `/api/v1/admin/auth/*` instead, for three reasons:

- An administrator name and a mailbox address could otherwise collide.
- The two flows unlock different things: a slot that holds a mailbox key versus a TOTP seal.
- Separate cookies keep a mailbox session from being promoted to an admin session.

`PATCH /domains/{id}` is not implemented: the only mutable domain attribute is the DKIM selector, which changes through `dkim-rotations`.

## Consequences

- An administrator can block, delete and provision accounts, and can make mail undeliverable by deleting aliases or domains, but cannot read existing mail. A malicious administrator with shell access can still change server code; that is outside the zero-access-at-rest promise ([whitepaper](../../whitepaper.md)).
- **Admin TOTP replacement needs the CLI.** `/api/v1/me/mfa/*` for administrators, WebAuthn for administrators, and admin roles beyond a single "administrator" role are open.
- **No audit trail yet.** Admin actions are not yet written to an audit log (plan step 17).

## Evidence

- `AdminStoreTest`: create/verify/delete, wrong password and unknown name, TOTP replay after reopening, plaintext scan of the file.
- `HttpAdminIT`:
  - TOTP-gated login and logout.
  - Separation of admin and mailbox tokens, and CSRF/Origin enforcement.
  - Domains with DKIM rotation and DNS guidance.
  - `428` and `412` versioning.
  - Step-up expiry and idle expiry.
  - Account provisioning with a working bootstrap password.
  - Blocking ends a live mailbox session and locks the mailbox.
  - Delayed deletion; alias create, update and delete.
  - Absence of mail, password, export and key routes.
- `AdminCommandTest`: the CLI in production mode, password mismatch, short and duplicate passwords, and a plaintext scan of the data directory.
- `MtaStsAndDkimTest`: `publishedRecord` for an existing and a missing selector.
