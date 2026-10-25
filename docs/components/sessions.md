# Authentication and Sessions

## Responsibility

Authenticate mailbox users across [IMAP](imap.md), [submission](smtp-submission.md), and [HTTP](http-api.md); own mailbox unlock leases and their cancellation. Use [identity](identity.md) for eligibility and [cryptography](cryptography.md) for unwrap, not a parallel credential store.

## Interfaces and Memory Ownership

- Accept credentials only after transport security is established. Return a scoped principal and an opaque closeable mailbox capability, never raw key arrays to protocol code.
- Reference-count compatible sessions through one mailbox coordinator; concurrent login must not create competing metadata writers or Lucene writers.
- A background task obtains a bounded child lease, checks cancellation, and closes it. No task may keep a mailbox unlocked indefinitely after the last user session ends.
- Keep HTTP session tokens, key handles, abuse counters, MFA challenges, and greylisting coordination in memory with bounded lifetimes. Restart invalidates sessions; persistent HTTP tokens must not silently retain unlock credentials.

IMAP/SMTP authentication mechanisms must actually provide an unlock secret over TLS (for example AUTH PLAIN). SCRAM alone cannot derive the private-key wrapping secret. App passwords use independent slots; distinguish their protocol capabilities from a primary credential. Default app slots should not authorize key administration.

## Abuse Controls and Revocation

Share per-source-IP attempt budgets and escalating delays across protocols and process roles. Enforce a global concurrent Argon2id/memory budget before starting work. Unknown users follow comparable bounded KDF work and generic errors. Avoid user-wide lockouts that let attackers exclude legitimate clients; control distributed guessing with resource admission and monitoring.

Trust forwarded client addresses only from explicitly configured, authenticated proxies. Define IPv4/IPv6 normalization and a bounded counter eviction policy.

Track the originating slot for each lease. Slot revocation closes sessions derived from that slot, cancels their child work, and blocks new leases. Account blocking invalidates all sessions. Password changes, recovery use, and rotations have explicit session-revocation policies. Remaining legitimate sessions may keep a mailbox unlocked, but revoked principals lose authorization immediately. None of this retracts copied secrets from an attacker.

On last-lease closure, close search readers/writers safely, clear decrypted caches, close metadata views, and best-effort wipe buffers. Timeouts and protocol disconnects follow the same release path. Java/library copies prevent a guarantee of complete erasure.

## Web Authentication

Require web MFA after password unwrap but before issuing a usable API session; promptly dispose of unauthenticated pending keys on failure/timeout. Select TOTP/WebAuthn and protected enrollment/recovery storage in an architecture decision. MFA protects online access, not offline decryption unless an approved key-contributing scheme is added. Admin MFA/authentication is separate from mailbox unlock.

## Acceptance Checks

Exercise simultaneous protocol logins, unknown users, exhausted KDF budgets, expired pending MFA, dropped connections, slot revocation, last-session logout, and cancelled indexing/export. No capability survives its authorization epoch; no observable account-enumeration error difference is introduced intentionally.