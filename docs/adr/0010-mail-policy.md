# ADR 0010: Inbound Mail Policy

Status: accepted for Phase 4. Content scores are unbenchmarked defaults, and the policy needs tuning against real traffic before production.

## Context

[PLAN step 11](../../PLAN.md) and the [mail policy component](../components/mail-policy.md) require:

- greylisting
- SPF, DKIM and DMARC with bounded DNS and a deliberate policy for temporary failures
- trustworthy `Authentication-Results`
- non-learning content rules that can be reloaded
- baseline dangerous-attachment checks
- spam routed to Junk instead of rejected

All of it must run while the recipient mailbox is locked.

## Decision

The `shem-policy` module is evaluated by `shem-smtp` after DATA (and, for greylisting, at RCPT), before anything is stored.

### Libraries

- **SPF:** jSPF 1.0.5. jSPF enforces the RFC 7208 ten-lookup limit.
- **DKIM:** jDKIM 0.5, through its streaming `verify(Headers, InputStream)` API. Shem reads the header block itself (at most 256 KiB and 1000 fields) and hashes the body as it streams. jDKIM's own `Message` parser would have loaded the whole body into memory. At most five `DKIM-Signature` fields are evaluated.
- **DNS:** dnsjava 3.6.3. Both jSPF and jDKIM query through Shem's `DnsResolver`, which uses:
  - a private cache with at most 10 000 entries and a 1-hour TTL cap (never dnsjava's process-wide cache)
  - a per-query timeout (`dns.timeout`, default 3 s) and one retry
  - at most 32 records per answer
- **DMARC:** no maintained Java DMARC library exists, so Shem has its own evaluator (`Dmarc`):
  - policy discovery at the From domain, then the organizational domain, using the public suffix list bundled with Guava
  - relaxed and strict alignment, `sp=`, and `pct=` sampling (outside the sample, the next lower policy applies)
  - the RFC 7489 rule that multiple records mean no policy
  - Reports (`rua`/`ruf`) are not sent.
- **MIME:** mime4j's token stream (`MessageScan`) decodes `text/*` parts (at most 1 Mi characters, at most 1000 parts) and lists attachment names and types. It never uses a storage provider, so it writes no temp files.

### Temporary-failure policy

- A DMARC policy lookup that fails temporarily gets `451 4.7.0`, so the sender retries.
- When a message fails DMARC under `p=reject`, but SPF or DKIM had a temporary error, it also gets `451` instead of a rejection.
- An unavailable block list contributes nothing.
- Temporary DNS failures therefore never cause a permanent rejection.

### Actions

| Check | Default | Setting |
| --- | --- | --- |
| DMARC fail with `p=reject` | `550 5.7.1` | `policy.dmarcReject` = REJECT, JUNK or TAG |
| DMARC fail with `p=quarantine` | Junk | — |
| Dangerous attachment | `550 5.7.1` | `policy.dangerousAttachments` = REJECT, JUNK or TAG |
| Content score ≥ `policy.junkScore` (5.0) | Junk, never rejected | — |

- **Dangerous attachments** are detected by:
  - executable and script extensions
  - disk images
  - macro-enabled Office extensions
  - double extensions
  - trailing dots or spaces
  - declared executable types
- **Built-in scores:**

  | Rule | Score |
  | --- | --- |
  | GTUBE | 1000 |
  | SPF fail | 3 |
  | SPF softfail | 1 |
  | DKIM present but none valid | 1 |
  | Not exactly one From author | 2 |
  | Missing Date | 1 |
  | Missing Message-ID | 1 |
  | Malformed or unbounded MIME | 2 |
  | Block-list hit | 3 |

### Content rules

- The optional `policy.rulesFile` holds rules of the form `NAME header|body|any "literal" score`, at most 1000 rules.
- Matching is a case-insensitive literal test and deliberately supports no regular expressions, so matching stays linear and no rules update can cause catastrophic backtracking. Regex support would need a linear-time engine (such as RE2/J) and its own decision.
- The file is validated whole at start-up, where an invalid file fails start-up. It is re-checked every minute: a valid change replaces the rules atomically, and an invalid one is rejected with a line number while the last known good rules stay active.
- Rules never learn from mail.

### Greylisting

- Greylisting applies at RCPT, after recipient validation.
- It is keyed by client network (IPv4 /24, IPv6 /64), envelope sender and recipient, with defaults of a 5-minute delay, a 4-hour retry window, a 35-day pass lifetime and at most 100 000 entries.
- Entries are keyed by an HMAC-SHA256 fingerprint under a random per-process key (`SymmetricKey.fingerprint`), so the table never holds addresses.
- The table is memory-only and lost on restart, which only means senders are greylisted again.
- It can be disabled with `policy.greylist=false`.

### Trace fields

- Shem prepends `Authentication-Results: <host>; spf=…; dkim=…; dmarc=…`, `X-Spam-Flag`, `X-Spam-Status` (score and rule names), and `X-Shem-Attachment` (reason codes) inside the encrypted message.
- Sender-controlled values are reduced to a safe token character set.
- Incoming `Authentication-Results` fields carrying Shem's authserv-id, and incoming `X-Spam-*`/`X-Shem-Attachment` fields, are removed byte-exactly (`HeaderRewriter`). The rewritten size is computed before delivery.
- Reason tags (`spam`, `dmarc-fail`, `dangerous-attachment`) also go into the encrypted receipt.

### Locked mailboxes

- Only global policy runs at receipt time; private per-user rules are not applied (the PLAN default proposal).
- Junk is a symbolic destination (`SpecialUse.JUNK`), resolved and created at import.

## Residual risk and limits

- **Resolver visibility:** every SPF, DKIM and DMARC query reveals sender domains and selectors to the configured resolver. Block lists (none by default) reveal client addresses to the list operator. No message content or content hash leaves the server.
- **Attachment checks are names and types only:** no archive inspection, no content sniffing, and no macro detection beyond file extensions. This is not antivirus; malware scanning (clamd) remains an optional, separately configured integration that is not implemented.
- **Rules see limited text:** decoded text parts only, with attachments ignored and HTML matched as raw markup.
- **Not implemented:** ARC, DMARC reports, SpamAssassin or Rspamd integration, IP reputation beyond optional block lists, and Sieve or user rules.
- **Untested scores:** the default scores and the 5.0 threshold have not been tuned against real traffic.
- **DMARC is Shem's own code** and needs the same external review as the cryptography profile.

## Evidence

- **`AuthenticationChecksTest`:**
  - SPF: pass, fail, softfail, none, permerror (two records), temperror, the lookup limit, and the HELO identity for the null sender.
  - DKIM: real RSA signatures from jDKIM's signer pass; a tampered body fails; a key-lookup failure gives temperror; signature count is bounded.
  - DMARC: alignment (relaxed and strict), organizational-domain `sp=`, `pct=` sampling, no record, temperror, and record parsing.
- **`ContentChecksTest`:**
  - Rules: parsing, validation, literal matching of regex metacharacters, and linear matching on adversarial input.
  - Greylist: deferral, pass, /24 aggregation, case-insensitivity, window expiry, and the size bound.
  - Attachments: detection cases.
  - MIME scan: base64 GTUBE and attachment listing.
  - Rewriting: byte-exact header rewrite with 8-bit headers and the computed size.
  - Rules reload: keeps the last known good rules.
- **`InboundPolicyTest`:**
  - Authenticated delivery with `Authentication-Results`.
  - A DMARC reject.
  - Quarantine and GTUBE going to Junk.
  - Temporary DNS failures giving `451`, never `550`.
  - Attachment enforcement as REJECT and as JUNK.
  - Atomic rules replacement.
  - Neutralized header injection.
- **`DnsjavaResolverTest`:** an unreachable server is a temporary failure within the timeout.
- **`InboundSmtpIT`, end to end:**
  - Forged `Authentication-Results` removed and real results recorded.
  - GTUBE delivered to Junk.
  - DMARC-reject and `.pdf.exe` messages refused before storage.
  - Greylisting defers only the first attempt.
- **Manual `serve` run with the real dnsjava resolver.** It found a dnsjava 3.6 `setSearchPath(null)` crash, which is fixed.
