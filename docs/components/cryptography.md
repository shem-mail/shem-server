# Cryptography and Key Management

## Responsibility and Collaborators

Provide reviewed cryptographic profiles, authenticated envelopes, key slots, and lifecycle operations to [sessions](sessions.md), [delivery](delivery.md), [stores](message-store.md), [search](search-index.md), and [HTTP](http-api.md). Protocol handlers never choose algorithms or manipulate raw private keys.

## Key and Format Contract

- One versioned asymmetric mailbox keypair; public key available to locked delivery, private key persisted only in authenticated password/app/recovery slots.
- Each slot includes version, algorithm identifiers, salt, bounded Argon2id parameters, and an authenticated private-key envelope. A successful unwrap verifies the credential; no separate mailbox password hash. Validate stored KDF parameters before allocation.
- Generate a fresh content key per stored message. Use an established authenticated streaming-encryption profile for blobs and a reviewed public-key envelope for the content key. X25519 is a candidate; post-quantum/hybrid profiles require a maintained standardized implementation and explicit decision.
- Wrap mailbox metadata and search keys under the mailbox hierarchy. Separate keys/purposes for blobs, metadata, receipts, and index files; define derivation/domain separation in the reviewed profile.
- Authenticate mailbox ID, object ID, format/key version, purpose, and relevant block position/length. Specify nonce uniqueness, final-length authentication, and replay/substitution boundaries. Never reuse a nonce/key pair across rewritten segments.

Do not equate independent AEAD blocks with complete file integrity: detect truncation, reordering, and cross-file substitution. Encryption does not by itself detect rollback of an entire valid historical store; document the external trust needed for freshness guarantees.

## Lifecycle Operations

Password changes rewrap the existing private key after step-up authentication. App passwords are high-entropy generated secrets with independent slots; recovery is another user-held secret/slot, not an admin reset. Slot lookup must support ordinary IMAP/SMTP usernames without exposing slot-specific credential oracles.

Enrollment generates a new keypair and atomically cuts over the public routing key after journaling a resumable rewrap job. Rotation must handle mail arriving under either key version and retain required old keys until all live references/receipts are migrated. Coordinate with [metadata](metadata-store.md) rather than rewriting immutable content blobs.

Keep mutable key envelopes in versioned encrypted records separate from immutable blob ciphertext; update references transactionally. Where an offline-delivery envelope initially accompanies a blob, define when it can be retired. Rewrapping does **not** revoke a copied old envelope or protect old ciphertext from someone who retained its content key. Protecting previously exposed content requires new content keys and re-encryption, a distinct operation not promised by ordinary rotation.

Deleting slots prevents future unwrap from current state but does not revoke already unlocked/copied keys. Session invalidation belongs to [sessions](sessions.md). Crypto-erase is effective only after removing every live envelope and compacting retained journals; backups retain their original access properties.

## Acceptance Checks

Use known-answer/library interoperability tests, wrong-credential tests, malformed-parameter tests, tamper/truncation/substitution tests, and nonce-uniqueness checks. Inject crashes throughout enrollment/rotation and prove delivery works across cutover without lost keys. Demonstrate that bootstrap credentials cannot decrypt new post-enrollment deliveries, while explicitly testing/documenting historical-copy limitations. Verify closeable secret buffers without claiming guaranteed JVM erasure.