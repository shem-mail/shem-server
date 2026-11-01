# HTTP Management and Self-Service API

## Responsibility and Scope

Expose an HTTPS server API for future clients and operators. No frontend, webmail, JavaScript bundle, or client-side key derivation is included. Use [identity](identity.md), [sessions](sessions.md), [cryptography](cryptography.md), [operations](operations.md), and [TLS](tls-certificates.md), never direct file/key access in route handlers.

Version business endpoints under `/api/v1` and publish a machine-readable OpenAPI contract when implementing them. The following is the proposed surface, not an already implemented API.

## Proposed Endpoint Groups

| Method and path | Principal | Contract |
| --- | --- | --- |
| `POST /api/v1/auth/login` | Public, rate limited | Password unlock or independent admin auth; only pending challenge until required MFA succeeds |
| `POST /api/v1/auth/mfa/verify` | Pending challenge | Complete MFA and issue scoped session |
| `POST /api/v1/auth/recovery` | Public, rate limited | Authenticate a user-held recovery slot; require credential replacement policy |
| `POST /api/v1/auth/logout` | Authenticated | Revoke session and release unlock lease |
| `GET /api/v1/me` | Authenticated | Own identity, enrollment state, capabilities; no secrets |
| `POST /api/v1/me/enrollment` | Bootstrap user | Complete required credential/keypair cutover |
| `PUT /api/v1/me/password` | User, step-up | Rewrap key slot; not a historical-data re-encryption operation |
| `GET, POST /api/v1/me/app-passwords` | User, step-up for creation | List non-secret slot labels or create one-time-displayed random app credential |
| `DELETE /api/v1/me/app-passwords/{slotId}` | User, step-up | Remove slot and invalidate its live sessions |
| `POST /api/v1/me/recovery-code` | User, step-up | Generate/replace a one-time-displayed user-held recovery secret |
| `POST /api/v1/me/key-rotations` | User, step-up | Start resumable rotation, return opaque job reference |
| `POST /api/v1/me/mfa/enrollment` | User/admin, step-up | Begin protected second-factor enrollment |
| `POST /api/v1/me/mfa/confirmation` | User/admin, step-up | Confirm factor before enabling it |
| `DELETE /api/v1/me/mfa/{factorId}` | User/admin, step-up | Enforce safe replacement/recovery policy |
| `POST /api/v1/me/exports` | User, unlocked, step-up | Start bounded streaming export negotiation; no plaintext export spool |
| `GET /api/v1/me/exports/{exportId}/content` | Owning user, unlocked | Stream agreed plaintext MBOX or versioned encrypted export |
| `DELETE /api/v1/me` | User, step-up | Request delayed destructive deletion with backup caveats |
| `POST /api/v1/admin/auth/setup` | Public, setup challenge | First login of a bootstrap administrator: replace the initial password and enroll TOTP ([ADR 0021](../adr/0021-first-run-bootstrap.md)) |
| `GET, POST /api/v1/admin/domains` | Admin | List/create owned server domains |
| `GET, PATCH, DELETE /api/v1/admin/domains/{domainId}` | Admin | Inspect/change/remove domain with dependency safeguards |
| `GET, POST /api/v1/admin/accounts` | Admin | List/create accounts with short-lived bootstrap flow |
| `GET, PATCH, DELETE /api/v1/admin/accounts/{accountId}` | Admin | Status/quota updates or delayed deletion; never decrypt/reset-to-recover |
| `GET, POST /api/v1/admin/aliases` | Admin | List/create authorized aliases |
| `PATCH, DELETE /api/v1/admin/aliases/{aliasId}` | Admin | Update/remove alias with loop validation |
| `POST /api/v1/admin/domains/{domainId}/dkim-rotations` | Admin, step-up | Rotate selector/signing key, expose DNS instructions |
| `GET /api/v1/admin/domains/{domainId}/dns` | Admin | Required DNS guidance without private keys |
| `GET /api/v1/jobs/{jobId}` | Owning principal | Sanitized status/progress; no arbitrary account/job visibility |

Admins cannot use user endpoints for another identity or export/read another user's mailbox. Do not add an admin password-reset-to-decrypt endpoint. An independent administrator bootstrap/recovery procedure belongs to operational provisioning and must not bootstrap access to user keys.

## HTTP Security and Contract Details

Use short-lived opaque in-memory sessions with Secure, HttpOnly, SameSite cookies for future browser use, CSRF tokens and Origin checks for mutations, and strict same-origin CORS by default. No tokens in URLs. If non-browser bearer support is added, specify it explicitly and preserve the same capability/revocation model. Credentials are never returned, logged, traced, or cached; one-time app/recovery responses use `Cache-Control: no-store` and disappear after response completion.

Validate typed schemas, content types, body/field limits, opaque IDs, and pagination. Use generic `401` errors for login, `403` for insufficient capability, `409` for version/state conflicts, `429` for admission limits, and sanitized problem-details errors. Use optimistic version checks for conflicting mutations and principal-bound idempotency keys for retryable job creation. Bound request duration and streaming backpressure.

Mutating key operations require fresh authentication, not merely a long-lived unlocked IMAP session. Rotation jobs pause safely if their lease expires; resumability must not require persisting plaintext credentials. Exports require an approved format: encrypted exports need an explicit user-controlled destination secret/public key, while plaintext exports are a deliberate authenticated download over TLS. Disconnect cancels export and releases leases; no plaintext disk staging.

HTTP also hosts narrowly scoped ACME/MTA-STS routes through [TLS](tls-certificates.md). Health endpoints return minimal unauthenticated liveness only; readiness/metrics/admin diagnostics are restricted and contain no account/message data.

## Acceptance Checks

Generate contract tests from OpenAPI; test every route against public, pending-MFA, ordinary user, app-slot, other-user, and admin principals. Cover CSRF/CORS, enumeration, replay/idempotency, revoked sessions, bootstrap restrictions, object-level authorization, oversized input, MFA changes, slow/disconnected export, and absence of secret fields in error/log/tracing output.