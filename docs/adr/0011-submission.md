# ADR 0011: Authenticated Submission, Local Recipients Only

Status: accepted for Phase 4. Remote recipients are added in plan step 13, together with the outbound queue and DKIM signing.

## Decision

`SubmissionRole` (in `shem-smtp`) runs two listeners:

- **Port 465:** TLS from the first byte.
- **Port 587:** STARTTLS, required before AUTH.

Both use the same James protocol handlers, DATA handling (`SpoolingEnvelope`, `SizeLimit`) and Netty transport as inbound SMTP ([ADR 0009](0009-inbound-smtp.md)).

### Authentication

- Shem's own `SubmissionAuth` replaces James's `AuthCmdHandler`. James's handler:
  - accepts AUTH whether or not TLS is active
  - hands passwords to hooks as `String`
  - writes user names and client addresses to an audit logger
- `SubmissionAuth` offers PLAIN and LOGIN, advertised and accepted only after TLS (`538 5.7.11` before TLS).
- The authorization identity must be empty or equal the authentication identity.
- Credentials are decoded into wiped byte and char buffers. They go through the shared `SessionService` path: the same key-slot unwrap, per-source limiter, KDF admission and dummy work as IMAP. There is no separate verification hash.
- The lease requires `Capability.SUBMIT`.
- Three failures close the connection.
- The lease lives as long as the connection. It is checked at MAIL, at RCPT and after DATA, so a revoked slot or blocked account ends the session (`421`) and nothing is sent.

### Sender authorization

- **Envelope sender:** must be an address the account owns, or an alias that lists the account as a permitted sender (`IdentityService.mayUseSenderIdentity`).
- **Null sender:** refused.
- **Header identities:** after DATA, every `From` and `Sender` address must pass the same check (`HeaderIdentities`). A message without exactly one valid `From` field is refused (`554 5.6.0`).

### Recipients

- Only local recipients are accepted.
- A remote recipient gets `550 5.7.0 Remote delivery is not available`. Nothing is queued, so no plaintext outbound queue exists yet.
- Limits per account:
  - `submission.maxRecipients` per message
  - `submission.recipientsPerHour`, an in-memory token bucket lost on restart
- Delivery goes through encrypted `DeliveryService` to INBOX, tagged `submission` in the receipt.
- `250` is sent only after every recipient's blob and receipt are durable, with the same partial-commit and retry ambiguity as inbound.

### Trace field

- `Received: by <host> (Shem) with ESMTPSA; <date>`.
- The submitting user's IP address and HELO name are not disclosed to recipients.
- `Return-Path` records the authorized envelope sender.

### Sent copies

Standard submission leaves Sent filing to the client (IMAP APPEND), which is the PLAN proposal. Shem never stores a second copy, so duplicates cannot arise. A server-managed Sent mode would need an explicit opt-in and its own ADR.

### Found while testing

The coordinator refuses new leases once its last lease starts closing, but it holds the metadata store until shutdown completes. A login that arrived in that window failed (`UNAVAILABLE`). `MailboxRegistry.attach` now waits, for at most 30 s, for a closing coordinator to finish before it opens the store again.

## Residual risk

- **Unavoidable copies:** James decodes each command line into a `String` before Shem sees it, and the user name stays a string. The password bytes in the AUTH line therefore exist briefly in an unwipeable copy. This is the same limitation as IMAP (ADR 0005).
- **Not yet covered:**
  - Rate limits across process roles; the limits are in memory and per process.
  - `Date` and `Message-ID` are not added to submissions that lack them (RFC 6409 section 8, optional).
  - No DKIM signing for local delivery. Signing applies to transmitted bytes in step 13.

## Evidence

- `SubmissionIT`:
  - AUTH and MAIL are refused before TLS on 587, and AUTH is advertised only after STARTTLS.
  - Wrong passwords, an unknown user, and a mismatched authorization identity fail, and the third failure disconnects.
  - PLAIN on 587 and LOGIN on 465 succeed.
  - A local send creates no client-address trace.
  - Envelope and header impersonation are refused, the null sender is refused, a missing From is refused, and the permitted alias is accepted.
  - Remote and unknown recipients are refused.
  - The per-account rate limit applies.
  - Revocation ends a live session.
  - Jakarta Mail (Angus) submits over STARTTLS with AUTH.
- `MailboxVerticalSliceTest.loginWhileTheLastSessionIsClosingWaitsForShutdown`: deterministic, using an extension that blocks shutdown. It fails without the registry fix.
