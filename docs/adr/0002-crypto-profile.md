# ADR 0002: Cryptographic Profile 1 and Key Hierarchy

Status: proposed. Implemented in `shem-crypto`; requires independent cryptographic review before production (PLAN Phase 6).

## Primitives (Google Tink 1.24.0, Bouncy Castle 1.86)

| Use | Construction | Code |
| --- | --- | --- |
| Public-key envelopes (content keys, receipt keys) | HPKE RFC 9180 base mode: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM; key version and context bound in HPKE `info` | `PublicKeyEnvelopes` |
| Blobs, snapshots, provisional spool | Tink AES-256-GCM-HKDF streaming AEAD; 64 KiB segments for blobs, 16 KiB for files; random per-stream salt and nonce prefix | `StreamingCipher` |
| Small records (slots, keyring, journal records, manifests, content-key wraps) | AES-256-GCM, 96-bit random nonce, 128-bit tag | `SymmetricKey.seal` |
| Key derivation | HKDF-SHA256 with `shem/hkdf/v1`, purpose label, and context | `SymmetricKey.derive` |
| Credentials | Argon2id v1.3 (Bouncy Castle) | `Argon2idKdf` |

No primitive or combiner is implemented in Shem. Raw-key imports use Tink's `@AccessesPartialKey` APIs; primitives are obtained through keyset handles and the public `*Config2026` configurations (no global registry mutation).

Associated data is a canonical, length-prefixed encoding of domain (`shem/aad/v1`), purpose, format version, and named fields (`AssociatedData`). It binds mailbox id, object id (blob/receipt/segment/snapshot), record index, data version, and slot parameters.

## Key hierarchy

```
credential --Argon2id--> KEK --AES-GCM--> master key            (one slot file per credential)
master key --AES-GCM--> keyring:                                (keys/keyring, generation-bound)
    mailbox private keys by version (X25519)
    data root keys by version
    slot descriptors (kind, label, created)
data root --HKDF--> journal segment keys, snapshot file keys, manifest key, content-key wrap key
public key (routing directory) --HPKE--> per-receipt key --> receipt body incl. per-message content key
```

- A successful slot unwrap is the credential check; there is no password hash.
- Each message gets a fresh content key. On import, the content key is wrapped under the data-root-derived wrap key and stored inside the encrypted metadata record; the receipt (which carried it) is then deleted.

## Enrollment and rotation

Enrollment (mandatory) and user rotation both: import pending receipts; generate a new master key, X25519 keypair (next version), and data root (next version); create a new password slot; atomically replace the keyring (commit point) with the new keys plus the retained old ones; delete stale slots; switch the routing public key; re-encrypt the metadata store under the new data root while rewrapping every content key; finally retire old private keys once no pending receipt needs them and the retention period after cutover has passed. Each step after the commit point is idempotent and re-run by `KeyLifecycle.resume` at the next unlock.

Because the master key changes, slots that wrap the old master (app passwords, recovery code) stop working and are removed; users must recreate them. Password changes only rewrap the master key.

## Explicit limitations

- Rewrapping/re-encryption does not protect message blobs or envelopes copied before the change: an administrator who knew the bootstrap password and kept a backup of the bootstrap slot and keyring can read pre-enrollment mail. Post-enrollment mail is sealed to the new key; `MailboxVerticalSliceTest.bootstrapCredentialAndOldKeyringCannotReadPostEnrollmentMail` exercises this.
- Removing a slot or deleting an account does not revoke keys an attacker already unlocked or copied. Crypto-erase requires removing every live envelope and compacting journals; backups keep their original access properties.
- Rollback of a whole valid historical keyring, manifest, or active journal tail is not detectable without external freshness state.
- Random 96-bit GCM nonces: per-key message counts are kept small by deriving per-segment and per-snapshot keys; slots and keyrings are rewritten rarely. Nonce uniqueness is tested statistically (`SymmetricKeyTest.noncesDoNotRepeat`).
- JVM erasure is best effort: `Secret.close()` wipes Shem's arrays; Tink `SecretBytes`, Bouncy Castle, JCE, and protocol libraries keep copies.

## Post-quantum

Tink 1.24 exposes an X-Wing HPKE KEM only through Conscrypt (native). Shem avoids native dependencies, so profile 1 is X25519 only. Envelopes carry a profile number, so a future profile 2 (e.g. X-Wing or ML-KEM hybrid from a maintained pure-Java implementation) can be added with re-sealing of keyrings and new deliveries; old blobs would need re-encryption to benefit. Decision deferred, not dismissed: harvest-now-decrypt-later remains a documented risk for profile 1.
