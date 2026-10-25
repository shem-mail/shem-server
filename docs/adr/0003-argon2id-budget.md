# ADR 0003: Argon2id Parameters and Admission

Status: proposed; the measurement below is from the development container, not the target VPS.

## Decision

- Default slot parameters: m = 64 MiB, t = 3, p = 1 (`Argon2Parameters.DEFAULT`). Configurable via `argon2.*`.
- Stored parameters are validated before allocation against `Limits.DEFAULT` (19 MiB–1 GiB, t ≤ 10, p ≤ 8).
- A single process-wide `KdfAdmission` memory budget (`kdf.budgetKiB`, default 4 × m) is shared by IMAP, submission, and HTTP; work that cannot be admitted within `kdf.maxWait` is rejected as THROTTLED.
- Unknown users and missing slots perform one dummy derivation with the configured parameters and return the same INVALID result.
- `AttemptLimiter`: 5 free failures per source per 15 minutes, then blocks doubling from 5 s up to 30 min; IPv6 counted per /64; at most 100 000 tracked sources (LRU). Successes do not reset counters. Accounts are never locked.

## Measurement (single-threaded, JDK 21, 4 vCPU container, Bouncy Castle 1.86)

| m | t | p | ms/derivation |
| --- | --- | --- | --- |
| 19 MiB | 2 | 1 | 43 |
| 64 MiB | 3 | 1 | 231 |
| 128 MiB | 3 | 1 | 547 |
| 256 MiB | 2 | 1 | 959 |

With the default budget, four derivations (~256 MiB) can run concurrently. Repeat on the target VPS before release and record the chosen values here.
