# Operations Runbook

Practical deployment notes for the current implementation. Design decisions live in the [ADRs](adr/README.md). Nothing here makes Shem production-ready: the PLAN Phase 6 gate (external review, restore drills on real hosts, benchmarks) is still open.

## Service user and host

- **Service user:** run as a dedicated non-root user (the container image uses `shem`). The data directory must be owner-only (`0700`); startup refuses anything else.
- **Memory hygiene:** keep core dumps, heap dumps and the attach API off (`-XX:-HeapDumpOnOutOfMemoryError -XX:-CreateCoredumpOnCrash -XX:+DisableAttachMechanism`, as in the Dockerfile). Also set `ulimit -c 0` and disable swap or encrypt it: unlocked keys and plaintext live in process memory.
- **Low ports** (25, 80, 443, 465, 587, 993): grant them narrowly, for example `CAP_NET_BIND_SERVICE` on the service, container port publishing, or forwarding. Shem changes no host settings.

## Configuration checklist

| Area | Keys | Notes |
| --- | --- | --- |
| TLS | `tls.hostNames`, plus either `tls.certificateChain` and `tls.privateKey`, or `acme.*` | Include `mta-sts.<domain>` names when hosting MTA-STS ([ADR 0018](adr/0018-acme-and-mta-sts.md)). |
| ACME | `acme.directory`, `acme.agreeToTerms=true`, `acme.challengeBind`, optional `acme.email` | Port 80 must reach `acme.challengeBind`. At first boot only port 80 opens until a certificate is issued. |
| Extraction | `extraction.enabled`, `extraction.sandbox`, `extraction.scratch` | Scratch must be a private, size-limited tmpfs. Start from `docs/examples/extraction-sandbox.sh` ([ADR 0019](adr/0019-attachment-extraction.md)). |
| Audit | `audit.stdout=true` | Mirrors audit records to stdout, so journald or a log shipper can keep an off-host copy ([ADR 0020](adr/0020-audit-and-backup.md)). |

## DNS

Per domain, the admin API lists the required records at `GET /api/v1/admin/domains/{id}/dns`: MX, SPF, DMARC, DKIM and, with MTA-STS, `mta-sts` and `_mta-sts`. Reverse DNS for the outbound address should match the mail host name.

## Administrators

- **Commands:** `shem --config FILE admin create NAME | list | delete NAME | audit-verify`, with the server stopped.
- **Lost TOTP:** delete and recreate the administrator. No administrator can decrypt mail or recover a user's password.

## Backups

1. Stop the server. Backups are offline, taken under the data-directory lock.
2. Run `shem --config FILE backup create /backups/2026-11-01 [--exclude-secrets] [--include-queue]`.
3. Copy the backup off-host and run `shem --config FILE backup verify DIR` before relying on it.
4. **Secrets:** a backup that includes them contains DKIM, ACME and admin keys. Prefer `--exclude-secrets` for routine backups and keep a separately protected secrets backup.
5. **Mailboxes** are ciphertext. Backups keep historical access for whoever holds old credentials; removing a slot does not reach into backups.

## Restore

1. Point `data.directory` at an absent or empty directory on the new host.
2. Run `shem --config FILE restore DIR`. The backup is verified first, copied into a staging directory and moved into place only when complete.
3. Start the server. Search and attachment indexes rebuild at each mailbox's next unlock.
4. Users sign in with their own passwords or app passwords. A restore cannot recover a lost password.

## Monitoring (no user data in any of these)

- **Certificates:** `GET /api/v1/admin/tls` shows the certificate expiry and renewal failures.
- **Logs:** warnings for renewal failures within 7 days of expiry, outbound queue problems, and extraction running without isolation (development only).
- **Audit:** `shem admin audit-verify` checks the audit chain. Startup also refuses a broken chain; investigate before moving the file aside.

## Upgrades

- **Before upgrading:** take a backup. Persisted formats are versioned, and readers reject unknown versions instead of guessing.
- **Rollback:** rolling back to an older release after the new one has written newer formats requires restoring that backup.

## Licensing and redistribution

Shem is licensed under Apache-2.0 (`LICENSE`, `NOTICE`). The release archive and the Docker image
(`/opt/shem`) also contain `licenses/THIRD-PARTY.txt`, which lists every bundled library with its
declared license, the `LICENSE`/`NOTICE` files those libraries carry (supplemented from
`shem-app/src/third-party/`), and the CycloneDX SBOM. All bundled libraries are under
Apache-2.0-compatible permissive licenses; dual-licensed ones (CDDL/EPL or GPL-2.0 with Classpath
Exception, LGPL or Apache-2.0) are used under the permissive option. When you redistribute the
image, keep these files with it.

The image's base layer is Ubuntu with the Eclipse Temurin JRE. Those components keep their own
licenses: the JRE is GPL-2.0 with Classpath Exception, and some Ubuntu packages are GPL/LGPL.
Their license files are in `/usr/share/doc/*/copyright` inside the image, and their sources are
available from Ubuntu (`apt-get source`, launchpad.net) and Adoptium (github.com/adoptium). If you
publish the image, point to those sources or mirror them, as your distribution requires.
