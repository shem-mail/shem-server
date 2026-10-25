# Identity and Administration

## Responsibility

Own domains, addresses, aliases, account status, enrollment state, quota policy, administrator roles, and public routing information. Own no decryption capability. [HTTP](http-api.md) exposes management; [sessions](sessions.md) handles credentials and unlocks; [cryptography](cryptography.md) owns keys.

## Interfaces and State

- Resolve canonical recipient addresses to opaque mailbox IDs, public-key versions, and delivery eligibility for [inbound](smtp-inbound.md) and [delivery](delivery.md).
- Authorize submission identities and aliases for [submission](smtp-submission.md); detect alias cycles and deny unauthorized relay routes.
- Support account lifecycle states such as pending enrollment, active, blocked, deletion pending, and deleted. Make state transitions and key-version cutover atomic and version checked.
- Manage domains, quota settings, alias changes, DKIM selector metadata, and DNS guidance. DKIM/TLS secrets belong to their owning components.

The minimum address-to-mailbox routing directory and public keys must be usable while users are locked and are therefore outside mailbox encryption. Document this identity leakage separately from encrypted mailbox metadata. Do not put folder names, UIDs, flags, envelopes, or plaintext message counters in the routing directory. Use opaque random filesystem names, not email addresses.

Administrators need independent authentication/MFA credentials because they need not own a mailbox. A dedicated admin verifier is not a second mailbox password hash. Store admin credentials and recovery policy separately; there is no admin mailbox-key escrow.

## Enrollment, Quotas, and Destructive Actions

Bootstrap credentials expire quickly and permit limited initial access. Mandatory enrollment rotates the bootstrap keypair and establishes user-owned slots through the key service. An initial-password change alone is insufficient. Decide whether mail is accepted before enrollment and warn about exposure of older copies.

Logical mailbox usage remains encrypted. For delivery while locked, investigate conservative physical-byte quota reservation using already visible ciphertext sizes and an opaque mailbox ledger; define padding/envelope overhead, aliases, simultaneous deliveries, cleanup, and HTTP reporting while locked. Do not introduce a plaintext per-message metadata database to simplify quota checks.

Blocking prevents new authentication and delivery according to explicit policy and revokes active leases. Account deletion/recreation requires a waiting period, step-up authorization, independent notification, and a new identity/key fingerprint and UIDVALIDITY. Audit these transitions through [operations](operations.md); an administrator cannot reset a password to unlock old data.

## Acceptance Checks

- Routing works while locked; alias cycles, cross-domain impersonation, and public-key substitution by ordinary users are rejected.
- Concurrent quota reservations cannot over-admit indefinitely; failure releases only the correct reservation.
- Enrollment cannot be skipped, and deleted identities cannot silently be reassigned through a create/update race.
- Admin API permissions do not imply access to mailbox reads, export, slots, or unlocked-key handles.