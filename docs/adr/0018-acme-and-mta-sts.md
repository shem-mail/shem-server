# ADR 0018: ACME Certificates, the Port-80 Listener, and MTA-STS Hosting

Status: accepted. **acme4j has not yet been run against a real ACME server** (staging CA or Pebble) in this repository; see Evidence.

## Context

[tls-certificates.md](../components/tls-certificates.md) asks for:

- ACME issuance and renewal with HTTP-01.
- Atomic, validated replacement and hot reload.
- A port-80 listener limited to challenges and safe redirects.
- A documented first boot without a certificate.
- Hosted MTA-STS policies.

The Phase 3 listener TLS (`ReloadableTlsContext`, `CertificateWatcher`) already validates and hot-reloads PEM files.

## Decision

### Configuration

ACME is enabled by `acme.directory` (an https URL). It also needs:

- `acme.agreeToTerms=true`: an explicit acceptance of the CA's terms.
- `acme.challengeBind`: the port-80 listener.

`acme.email` is optional. With ACME, `tls.certificateChain` and `tls.privateKey` must be absent: the listener files are `data/acme/live/{chain,key}.pem`. `tls.hostNames` lists every name the certificate must cover, including `mta-sts.<domain>` for each domain whose MTA-STS policy is hosted.

### Issuance (`Acme4jAuthority`, `shem-tls`)

- **Account and order:** acme4j 5.1.0, HTTP-01 only. The account key is EC P-256, created once at `data/acme/account.pem` (owner-only, private plus public key, PEM). The client registers or reuses the account, orders all host names, publishes each token in `Http01Challenges`, triggers the challenge, and waits up to 2 minutes per step.
- **Domain key:** a fresh EC P-256 key per issuance, put into the CSR by acme4j (which uses Bouncy Castle, now a runtime dependency of `shem-tls`).
- **Tokens:** withdrawn as soon as the order's authorizations finish, whatever the outcome.
- **Logging:** acme4j logs through SLF4J. No SLF4J provider is shipped, so its logging is a no-op. This is deliberate: its debug output includes protocol traffic. SLF4J prints a one-line notice saying so.
- **Not used:** DNS-01, wildcards, External Account Binding, ACME profiles and ARI-driven renewal. Each would be a separate decision.

### Atomic replacement (`CertificateGenerations`)

- **Install:** each certificate is written complete into `data/acme/gen-N/` (`key.pem` owner-only, `chain.pem`), fsynced, and validated with the same checks as listener loading (`CertificateBundle`: validity, key match, every host covered, chain links). Only then is it published, by atomically renaming a new symbolic link over `live -> gen-N`.
- **Crash safety:** a crash at any point leaves `live` on the old or the new generation, never on a mismatched pair. An abandoned partial generation is never referenced.
- **Rejection:** a rejected certificate (for example, the wrong host) is deleted and `live` is untouched.
- **Retention:** the live and previous generations are kept; older ones are removed.

### Renewal (`CertificateRenewal`)

- **When:** renewal is due two thirds into the live certificate's lifetime, minus a random jitter (chosen once per certificate) of up to 1/20 of the lifetime. It follows whatever lifetime the CA issues, with no fixed day counts.
- **Checks:** every 5 minutes. Failures back off from 5 minutes, doubling to at most 6 hours. A failure never touches the live certificate.
- **Logging:** failures log only the exception class. When there is no valid certificate, or less than 7 days remain, the log is a `WARNING` naming the expiry time.
- **Reload:** after a successful install the listeners reload immediately. The file watcher would also pick it up. Established sessions and in-memory abuse/greylist state are unaffected, because the `SSLContext` is reused.
- **Observability:** `GET /api/v1/admin/tls` reports `notAfter`, `renewAt`, `nextAttempt`, `consecutiveFailures`, `lastError` (exception class only) and `lastSuccess`. It never includes keys, tokens or CA account data. Without ACME, the same route reports the configured certificate's expiry and last reload failure.

### First boot

If no valid live certificate exists:

1. `serve` starts only the port-80 listener.
2. It requests a certificate, retrying with backoff until one is live or the process is told to stop.
3. Only then does it open the TLS listeners (IMAP, SMTP, submission, HTTPS).

No listener runs with a placeholder certificate, so no credentials can be accepted on an untrusted certificate. The server holds no mail-facing ports until issuance succeeds. That is visible in the log, and the operator must make port 80 reachable from the CA.

### Port 80 (`ChallengeRole`, `shem-http`)

- `GET`/`HEAD` on `/.well-known/acme-challenge/{token}` returns the key authorization while the token is active, and `404` otherwise. Tokens must match `[A-Za-z0-9_-]{1,128}`, and at most 100 are active.
- Any other `GET`/`HEAD` gets a `301` to `https://<host><path>`, with no authentication and no API:
  - `<host>` is the request's Host only if it is one of `tls.hostNames`; otherwise it is the first configured host.
  - The path is kept only if it is a plain absolute path of at most 2048 printable characters that does not start with `//` and contains no `\`; otherwise it becomes `/`.
- Other methods get `405`.
- The listener uses a bounded pool of 4 threads with a queue of 64; excess requests are dropped.

### MTA-STS hosting

- **Configuration:** `mtaSts.mode` (`enforce`, `testing` or `none`) and `mtaSts.maxAge` (default 7 days) enable policy hosting. This requires `http.bind`.
- **Route:** `GET /.well-known/mta-sts.txt` on the HTTPS listener answers only when the request host is `mta-sts.<d>` for a local domain `d`. The policy names the first TLS host as `mx`.
- **Policy id:** the first 20 hex digits of the policy text's SHA-256, so it changes exactly when the policy does.
- **DNS guidance:** the admin DNS endpoint adds `mta-sts.<d> CNAME <mail host>` and `_mta-sts.<d> TXT "v=STSv1; id=..."`.
- **Certificate coverage:** if the certificate doesn't cover `mta-sts.<d>`, senders' policy fetches fail. RFC 8461 treats that as "no policy", which is the safe failure.

## Consequences

- **Port 80:** binding port 80 as non-root remains an operator choice (a capability, container port publishing, or forwarding); Shem does not change host settings. Source-IP preservation behind forwarding is untested.
- **Dynamic names:** host names are static configuration. Adding a domain with MTA-STS means adding `mta-sts.<domain>` to `tls.hostNames` and restarting, which triggers issuance for the new name set.
- **Backups:** `data/acme/` (account key and listener keys) needs separate, service-only protection in backups, like `dkim/`.

## Evidence

- **`CertificateRenewalTest` (fake CA):**
  - First issuance makes a valid live generation behind a symlink, with an owner-only key; the challenge is visible during the order and withdrawn after.
  - Renewal happens only when due and always uses a fresh key.
  - A failed renewal keeps the live certificate, backs off (5 then 10 minutes), and recovers.
  - Backoff is capped.
  - A wrong-host certificate is never made live, and its generation is removed.
  - A crash before the swap leaves the old generation live, and the next install skips past the partial generation.
  - The account key round-trips through its file with owner-only permissions.
  - Tokens are validated and their number is bounded.
  - acme4j against an unreachable directory gives a reported `AcmeNetworkException` and backoff. This proves the acme4j, jose4j and Bouncy Castle runtime classpath loads; it does not prove an issuance.
- **`HttpAcmeIT`:**
  - Port 80 serves only active tokens.
  - Redirects go only to configured hosts, whatever the `Host` header.
  - Unsafe redirect paths collapse to `/`.
  - `POST` to port 80 gets `405`.
  - The MTA-STS policy text is served only on policy hosts of local domains.
  - Policy ids track the policy text.
  - The admin TLS status and DNS guidance are correct.
- **`ShemConfigTest`:** ACME and MTA-STS configuration validation.
- **`OpenApiContractIT`:** covers `/.well-known/mta-sts.txt` (on its virtual host) and `/api/v1/admin/tls`.
- **Packaged-jar smoke run:** with an unreachable CA, only port 80 opened and served redirects, HTTPS stayed closed, the failure was logged with only the exception class, and shutdown during the wait was clean.
- **Not run:** `AcmePebbleIT` performs a real HTTP-01 issuance against Pebble when `-Dshem.pebble.directory` is set. Building Pebble in this environment was not permitted, so it was skipped. A run against Pebble or a CA staging environment is still required before relying on ACME.
