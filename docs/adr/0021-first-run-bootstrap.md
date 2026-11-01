# ADR 0021: First-Run Bootstrap of the Initial Administrator

Status: accepted. Amends [ADR 0016](0016-admin-api.md), where `shem admin create` was the only way to create an administrator. The container image has not been built in CI with these changes yet.

## Context

ADR 0016 creates administrators offline with `shem admin create`. In a container, that means a separate interactive `docker run` against the data volume before the server first starts. The project owner wants a new installation to work like database images such as MySQL: an initial password is configured, it is used only when the data directory is new, and it means nothing on later starts.

The constraints from AGENTS.md and the component specifications still apply:

- No separate password-verification hash.
- Configuration files must not contain passwords.
- Credentials are never logged.
- Administrators get no route to mailbox keys.
- Persisted formats are versioned and older data stays readable.

## Decision

### When the bootstrap runs

- Only `serve` runs it. It runs after the data directory is opened and locked, and before any listener opens.
- It applies only to a **fresh data directory**: neither `routing/directory.bin` nor `admin/admins.bin` exists.
  - On any other start it does nothing. If `bootstrap.adminPasswordFile` or `bootstrap.domain` is set, it prints that the settings are ignored.
  - Deleting the last administrator does **not** make the directory fresh again. Otherwise "delete the last admin and restart" would revive a known initial password.
- If an administrator was created with `shem admin create` before the first `serve`, the bootstrap is skipped.
- `bootstrap.enabled=false` turns it off.

### Configuration

| Key | Default | Meaning |
| --- | --- | --- |
| `bootstrap.enabled` | `true` | Whether a fresh data directory gets an initial administrator |
| `bootstrap.adminName` | `admin` | Name of the initial administrator, using the ADR 0016 name rules |
| `bootstrap.adminPasswordFile` | none | File holding the initial password (at least 14 characters; one trailing line ending is removed). Meant for Docker/Compose secrets |
| `bootstrap.domain` | none | First mail domain to create, for example `example.org`. The host name for TLS and the HTTP origin stays `tls.hostNames` |
| `bootstrap.validity` | `P3D` | How long the initial password stays valid (between `PT1H` and `P30D`) |

- **Initial password from a file, not from an environment variable or the configuration.** Environment variables show up in `docker inspect` and `/proc/<pid>/environ`, and the configuration file must not hold passwords. The file is read as bytes and decoded into a wipeable `char[]`. It is never read again after the first run and can be deleted.
- **Generated password when no file is configured.** The server generates a 24-character password (120 bits) and writes it owner-only (`0600`) to `data/admin/initial-password`. It prints the file's path, never the password. `AdminStore` deletes the file as soon as no administrator is left in setup state, which happens after setup completes or the administrator is deleted.
  - This is a plaintext credential at rest, a deliberate and temporary exception. It sits inside the owner-only data directory, protects no mail, and grants only the setup step below.
  - It is comparable to the bootstrap passwords that administrators already receive for mailboxes.
- **Optional first domain.** If creating the domain fails, the administrator still exists and startup continues with a message; the domain can then be created through the admin API. No DKIM key is generated: use `POST /api/v1/admin/domains/{id}/dkim-rotations`.

### Setup state (`AdminStore`, `SHAD` version 2)

- **No usable second factor yet.** The initial administrator's key slot has kind `BOOTSTRAP` and wraps a random admin key under the initial password. It has no TOTP secret and carries a setup expiry.
- **Logins after expiry fail.** After expiry the initial password is refused exactly like a wrong password. This includes logins that started before expiry and try to finish after it.
- **What `completeSetup` checks**, before any change:
  - the administrator is in unexpired setup state;
  - the new password has at least 14 characters;
  - the TOTP code matches the offered secret;
  - the new password does not open the old bootstrap slot, which costs one extra Argon2id derivation.
- **What `completeSetup` does:**
  - creates a `PASSWORD` slot under the new password around a **fresh** admin key;
  - seals the TOTP secret under that key (same `admin-factor` context as ADR 0016);
  - records the accepted TOTP step, so the setup code cannot be replayed at the next login;
  - persists the administrator as active.
- **File format:**
  - Version 2 adds a state byte and a setup expiry per administrator.
  - The store writes version 1 whenever no administrator is in setup state. Deployments without a bootstrap therefore keep a file that earlier releases can read, and a completed bootstrap returns to version 1.
  - Both versions are read. Unknown versions, and a state that does not match the presence of a TOTP seal, are rejected.
- The TOTP seal's authenticated context keeps version 1, independent of the file version, so existing seals stay valid.

### First login over HTTP

1. `POST /api/v1/admin/auth/login {name, password}` with the initial password returns `{"mfaRequired": false, "setupRequired": true, "challenge", "totpSecret", "otpauthUri"}`.
   - The challenge holds the verified admin key and the offered TOTP secret in memory for 15 minutes, with 5 attempts.
   - It can never become a session: `POST /auth/mfa/verify` with a setup challenge returns `409`.
2. `POST /api/v1/admin/auth/setup {challenge, newPassword, totp}`:
   - A wrong code returns `401` and uses up an attempt; it also counts toward the per-IP failure limit.
   - A short or unchanged password returns `409`.
   - Success returns `204`, ends the challenge and issues **no** session.
3. The administrator then logs in normally with the new password and a later TOTP code.

This mirrors mailbox enrollment (ADR 0013), where the bootstrap session can only enroll and then ends. Using a challenge instead of a restricted session means no new session kind is needed.

Audit records: `bootstrap admin.create` and `bootstrap domains.post` at first run, `admin:<name> auth.setup` for each setup attempt. The OpenAPI contract goes to version 1.1.0, an additive change.

### Container defaults

- The image creates `/data` (owned by `shem`, mode `0700`), declares it as a volume, and defaults to `CMD ["--config", "/etc/shem/shem.properties", "serve"]`.
- `docs/examples/shem.properties` and `docs/examples/compose.yaml` show a first installation:
  - certificate through ACME;
  - initial password as a Compose secret;
  - `bootstrap.domain` set.
- `ShemConfigTest` checks that the example configuration is valid.

## Consequences

- **Exposure window.** Once ACME issues a certificate, the admin API is reachable while the initial password still works. The password is chosen by the operator (at least 14 characters) or generated (120 bits), it expires, and per-IP limits and Argon2id admission apply. Operators should still complete setup right after the first start.
- **Who can complete setup.** Whoever knows the initial password can complete setup and choose the TOTP secret. This is the same trust placed in anyone holding `shem admin create` access.
- **Expired setup.** If the initial password expires unused, the bootstrap does not run again. Use `shem admin delete admin` and `shem admin create` with the server stopped.
- **Rollback.** A data directory with an unfinished setup holds a version 2 admin store, which releases before this ADR cannot read. Complete the setup (the file returns to version 1), or delete the pending administrator, before rolling back.
- **No mailbox access.** The bootstrap gives administrators no mailbox access; ADR 0016's separation is unchanged.

## Evidence

- `AdminStoreTest`:
  - setup flow (wrong code, short or unchanged password, completion, replay of the setup code, persistence);
  - expiry, including a login started before expiry;
  - generated password file (mode `0600`, removed after setup or deletion);
  - version 1 compatibility and rejection of unknown versions;
  - plaintext scans.
- `HttpAdminIT`:
  - setup challenge offered at login;
  - setup challenge refused by `/auth/mfa/verify`;
  - wrong code, short and unchanged password;
  - completion without a session, then a normal login;
  - expired initial password;
  - normal challenge refused by `/auth/setup`.
- `FirstRunBootstrapTest`:
  - password file and first domain, with a plaintext scan of the data directory;
  - later starts ignored, including after deleting the last administrator;
  - CLI-created administrator skips the bootstrap;
  - generated password;
  - `bootstrap.enabled=false`;
  - missing or short password file creates nothing.
- `ShemConfigTest`: defaults, validation, and the Docker example configuration.
- `OpenApiContractIT`: the new route is documented and reachable.
