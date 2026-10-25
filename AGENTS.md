# Agent Expectations

## Scope and Sources

- This repository is Shem's server, not a browser/mobile client. Include an HTTP API; do not add frontend code or a webmail UI.
- Read [PLAN.md](PLAN.md), the relevant [component specifications](PLAN.md#component-catalog), and the [whitepaper](whitepaper.md) before implementation. Record unresolved choices instead of silently weakening requirements.
- The repository contains documentation plus a minimal Maven/Docker scaffold (`shem-app` entry point, no protocol roles). Candidate libraries in the parent `dependencyManagement` are pinned but unvalidated until Phase 0. Do not claim compilation, tests, benchmarks, or library compatibility have passed until actually executed.

## Modern Java Baseline

- Proposed baseline: Java 25 LTS, no preview features, Maven 3.9 multi-module build (no Maven Wrapper; developers and CI use a pinned Maven installation). Confirm compatibility in Phase 0; document any approved change to Java 21 LTS.
- Pin compiler release, toolchains, plugins, and dependencies. Use UTF-8 and reproducible build settings. Prefer maintained libraries and standard JDK APIs; verify upstream documentation for the selected versions.
- Keep domain services independent of James, HTTP, persistence implementations, and dependency-injection frameworks. Inject dependencies through constructors; compose at the runtime boundary. No global service locators or mutable static state.
- Use records for immutable value types, sealed types for closed alternatives where helpful, descriptive names, explicit ownership, and narrow interfaces. Do not expose mutable byte arrays as ordinary value objects.
- Use try-with-resources for files, streams, sessions, and key leases. Preserve cancellation/interruption and make failure handling explicit; no swallowed exceptions or catch-all success responses.
- Prefer straightforward code over speculative abstractions. Use virtual threads only for appropriate blocking workloads. Bound executors, queues, caches, message sizes, parser work, and cryptographic concurrency. Never block a reactive/event-loop thread.
- Add nullability/static analysis and one enforced formatter at scaffolding time. Avoid Lombok, native persistence engines, and unnecessary frameworks unless an architecture decision justifies them.

## Security Rules

- Zero-access at rest is the promise, not zero-knowledge or protection from root/live memory inspection. Never overstate JVM key erasure or revocation of already copied secrets.
- Centralize cryptography and storage enforcement. Use reviewed AEAD/envelope constructions and a cryptographic RNG, version formats, authenticate context, and test nonce uniqueness and tampering. Do not implement primitives or ad hoc hybrid combiners.
- Mailbox contents, headers, folder names, flags, delivery metadata, and indexes must never persist as plaintext. Inspect dependencies for implicit temp files/caches. The outbound queue is the sole mail-content exception and must remain isolated.
- Never log credentials, keys, tokens, addresses, subjects, message bodies, raw protocol traffic, or content-derived identifiers. Redact errors and prevent request/response tracing of sensitive API routes.
- Avoid immutable strings for secrets where APIs permit; use narrowly scoped wipeable buffers and closeable key leases. Document unavoidable library copies. Disable core/heap dumps and require protected swap/tmpfs operationally.
- Require TLS before authentication. Apply shared per-IP abuse controls and bounded Argon2id admission across protocols. Do not introduce a separate mailbox password-verification hash.
- Administrators cannot decrypt mail or reset a password to recover an existing mailbox. Enrollment, rotation, slot revocation, account recreation, and backup limitations require explicit tests.
- Reuse James modules only through approved adapters; do not adopt its default stores, queues, or server distribution. No persistent inbound plaintext spool and no mandatory external database.
- Run as non-root with isolated roles. Optional external scanners are opt-in trust-boundary exceptions, never hidden defaults.

## Tests and Delivery

- Add focused JUnit Jupiter tests with each behavior change. Use integration tests for storage, protocol adapters, HTTP authorization, and component contracts. Prefer deterministic clocks and failure injection over timing sleeps.
- Test wrong keys, corrupted/truncated/reordered ciphertext, crash boundaries, disk-full conditions, concurrent delivery/session/logout/rotation, and resource exhaustion. Include filesystem plaintext-marker scans, while recognizing they are not a cryptographic proof.
- Verify SEARCH completeness during index lag, UID/modseq semantics, no open relay, client interoperability, and backup/restore consistency. Use synthetic mail only; never commit real messages or credentials.
- Keep unit tests fast; separate integration, fuzzing, interoperability, and benchmark suites. Do not replace correctness tests with benchmarks.
- When the build exists, require `mvn verify` as the normal gate and `mvn -pl <module> -am test` for focused iteration. Configure formatting, static analysis, integration tests, and dependency checks in the lifecycle before advertising these commands as working.
- CI must pin its JDK/build environment, scan dependencies/secrets, publish an SBOM, and build a versioned distribution. Supply-chain exceptions need documented rationale and review.
- Version persisted formats and HTTP contracts. Include compatibility tests and migration/rollback behavior with changes; never silently rewrite existing user data.
- Keep edits scoped, preserve unrelated changes, and update nearby contracts/docs. Report what was actually validated and any remaining blocker. Do not commit or change the planned architecture without authorization.