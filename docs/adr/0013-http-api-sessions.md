# ADR 0013: HTTP API Sessions and Self-Service (Step 14, First Slice)

Status: accepted for the self-service slice. MFA is decided in [ADR 0014](0014-mfa.md), admin authentication and endpoints in [ADR 0016](0016-admin-api.md), exports, rotation jobs, and the OpenAPI contract in [ADR 0017](0017-exports-jobs-openapi.md).

## Decision

### Server

`shem-http` uses the JDK's `com.sun.net.httpserver.HttpsServer` and no web framework:

- TLS 1.2 or 1.3 from the reloadable listener certificate
- a bounded pool of virtual threads, with a bounded queue
- Jackson for JSON: trees only, no data binding, duplicate keys and trailing tokens rejected
- request bodies capped at 64 KiB, `application/json` only

Every response carries:

- `Cache-Control: no-store`
- `X-Content-Type-Options`, `Referrer-Policy: no-referrer`, `X-Frame-Options`
- a `default-src 'none'` CSP
- HSTS

No CORS headers are ever sent. Errors are RFC 9457 `application/problem+json` documents with fixed, non-identifying details. Nothing about a request is logged.

### Sessions

An API session is an opaque 256-bit random token that maps, in memory only, to a `MailboxLease`:

- The unlocked keyring stays in the existing mailbox coordinator. Key material never leaves the server and is never part of a token.
- The session map is keyed by a keyed fingerprint of the token (`SymmetricKey.fingerprint`, per-process key), so the map holds no usable token.
- **Ending a session:** logout, an idle timeout (`http.idleTimeout`, 30 min), an absolute lifetime (`http.absoluteLifetime`, 12 h), lease revocation (slot removal, account block, key rotation) and shutdown all close the lease. When no IMAP, submission or API session remains, the mailbox locks.
- A restart ends every session. There are no refresh or "remember me" tokens.
- Session counts are capped per account and in total.

### Login and credentials

- `POST /api/v1/auth/login` calls the new `SessionService.authenticatePrimary`. It accepts only the primary password or a bootstrap password, never an app password, so a credential given to a mail client cannot reach account management.
- The login path is shared with IMAP and submission: limiter, KDF admission, dummy work, and a generic `401` that is identical for a wrong password, an unknown user and an app password.
- `POST /api/v1/auth/recovery` gives a session whose only capability is key administration. `PUT /me/password` consumes the recovery code and ends every session of the mailbox.

### Browser and non-browser clients

- **Browsers:**
  - The session cookie is `__Host-shem-session` with `Secure; HttpOnly; SameSite=Strict; Path=/`.
  - Mutations need the session's `X-CSRF-Token` (returned by login and `/me`, compared in constant time).
  - An `Origin`, when present, must equal `http.origin` (default `https://` plus the first TLS host name).
  - `Sec-Fetch-Site: cross-site` is refused.
- **Non-browser clients** send `"bearer": true` at login. They receive the token in the body instead of a cookie and use `Authorization: Bearer`. CSRF does not apply, but the timeouts and revocation are the same.

### Step-up

The following operations need a credential check within the last 5 minutes, otherwise `currentPassword` in the body (`SessionService.verifyPassword`):

- password change
- app password creation and deletion
- recovery code creation

### Endpoints in this slice

| Endpoint | Purpose |
| --- | --- |
| `POST /api/v1/auth/login`, `/auth/recovery`, `/auth/logout` | Session start (password or recovery code) and end |
| `GET /api/v1/me` | Own identity, state, capabilities, session expiry |
| `POST /api/v1/me/enrollment` | Bootstrap sessions only. The session ends and the user logs in with the new password |
| `PUT /api/v1/me/password` | Change password |
| `GET, POST /api/v1/me/app-passwords`, `DELETE /api/v1/me/app-passwords/{id}` | List app passwords (labels only), create one (password shown once), delete one (ends its sessions) |
| `POST /api/v1/me/recovery-code` | Create a recovery code (shown once) |
| `GET /healthz` | Liveness |

## Unresolved, recorded rather than weakened

- **MFA:** superseded by [ADR 0014](0014-mfa.md). A second factor is mandatory, and the `http.allowWithoutMfa` opt-out has been removed.
- **Admin side:** implemented separately from mailbox unlock in [ADR 0016](0016-admin-api.md).
- **Not yet built:** exports, rotation jobs, OpenAPI.
- **JDK server limits:** the JDK server's own header and time limits are its defaults (`sun.net.httpserver.*`).

## Residual risk

- **Unavoidable string copies:** the password arrives in a JSON string, a Jackson `TextNode`, which can't be wiped; raw body bytes are wiped after parsing. One-time app passwords and recovery codes are written into the response as strings. These are the same limits as the other protocols.
- **Live memory:** an unlocked session keeps the mailbox decryptable in server memory for as long as the session lives, by design. The threat model does not cover live memory inspection.

## Evidence

- `HttpApiIT`, over real TLS with `java.net.http.HttpClient` and a controllable clock:
  - The session keeps the mailbox unlocked until logout, then it locks. Cookie flags and security headers are set; there are no CORS headers.
  - Failures are indistinguishable for a wrong password, an unknown user and an app password.
  - A bootstrap session can only enroll; a weak password gets `409`; after enrollment the old session and the bootstrap credential are gone.
  - A cross-origin login, a wrong or missing CSRF token, and a cross-site fetch are refused. A bearer client works without CSRF.
  - Step-up gives `403` without a password, `401` with a wrong one, and success with the right one. App password creation works, deletion revokes the app's live lease, and a second deletion gives `404`.
  - Idle expiry and mailbox revocation end the session.
  - The recovery code flow is single use and ends other sessions.
  - Validation cases (`400`, `413`, `415`, `404`, `405`) and the per-account session cap (`429`) behave as specified.
- `MailboxVerticalSliceTest`: app passwords never open an API session.
- Manual: packaged `serve` with `http.bind`, using curl for login, `/me`, logout, and `/me` returning `401` afterwards.
