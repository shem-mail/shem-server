# TLS and Certificate Management

## Responsibility and Interfaces

Own listener TLS settings, ACME account/certificate lifecycle, HTTP-01 responses, certificate distribution/reload, and hosted MTA-STS policy. Supply [inbound](smtp-inbound.md), [IMAP](imap.md), [submission](smtp-submission.md), and [HTTP](http-api.md). Remote delivery TLS policy belongs to [outbound](outbound-delivery.md).

## Listener Contract

- Port 993 IMAP and port 465 submission use implicit TLS.
- Port 587 requires STARTTLS before credentials; no downgrade to cleartext AUTH.
- Port 443 hosts the HTTPS API and valid host-specific MTA-STS policy routes, such as `/.well-known/mta-sts.txt` on the policy host.
- Port 25 offers STARTTLS opportunistically; mandatory encryption would reject legitimate legacy senders. Do not misrepresent it as guaranteed confidentiality.
- Port 80 serves only active HTTP-01 challenge tokens and safe redirects to HTTPS, not authentication or business APIs. Validate hostnames and construct redirects from configured hosts, not untrusted Host headers.

Use modern supported TLS versions/ciphers and certificate hostname validation. Do not invent a fixed cipher list divorced from the chosen JDK/client compatibility target.

## Certificate Lifecycle and Persistence

Evaluate maintained acme4j against an ACME staging server in Phase 0. Start with HTTP-01; DNS-01/wildcards and alternate challenges are optional future decisions, not assumptions about provider availability in 2026.

Persist ACME account and TLS private keys outside mailbox stores with service-account-only permissions and separately encrypted backups. Validate certificate chains, names, and key matches before atomic replacement. Distribute only required certificates/keys to listener roles; never send mailbox keys. Renew using supported ACME Renewal Information or a validity-aware safety margin, with jitter/backoff and expiry alerts.

Hot reload must preserve established sessions and in-memory abuse/greylisting state. Failed renewal keeps a still-valid certificate; expiry must not enable insecure login or disable verification. Document initial boot when no certificate is available and ensure challenge handling does not require an already valid HTTPS certificate.

## Deployment and Acceptance Checks

Run as non-root. Choose and document low-port binding through a narrowly scoped capability, container publication, dedicated-host configuration, or port forwarding; test original source IP and IPv6 behavior. Do not modify host-wide settings automatically. See [operations](operations.md).

Test ACME staging issue/renewal, rejected challenges, restart during replacement, invalid new chains, hot reload during IMAP/submission/API sessions, expired certificates, untrusted redirect hosts, source-IP preservation, and HTTP-01 route isolation. Do not pin renewal behavior to unverified certificate-lifetime dates from the whitepaper.