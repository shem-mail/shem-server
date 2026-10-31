# ADR 0001: Java Baseline and Build

Status: accepted; amended (2026-10-31): the target is Java 21 LTS.

## Decision

- Target Java 21 LTS (`java.release=21` in the parent POM), no preview features. The enforcer requires JDK 21 or newer to build.
- JDK 25 is a supported build and runtime JDK: release-21 bytecode runs on it, and CI builds on both. Do not use Java 22+ language features (unnamed variables, flexible constructor bodies, module imports) or APIs (stream gatherers, `Console.isTerminal`, PEM API); the compiler rejects them at release 21.
- Maven 3.9 multi-module build without a wrapper. Gates in the lifecycle: enforcer (Maven/Java versions, plugin versions, dependency convergence), Error Prone + NullAway (JSpecify mode, `-Werror`), Spotless with google-java-format, Surefire/Failsafe, CycloneDX SBOM for `shem-app`.
- Error Prone on JDK 21 needs `-XDaddTypeAnnotationsToSymbol=true` and the `--add-exports/--add-opens` flags in `.mvn/jvm.config`; both are harmless on JDK 25.

## Evidence

This development environment (Claude Code cloud) provides only OpenJDK 21.0.12 and Maven 3.9.11; JDK 25 downloads are blocked by its network policy. Plain `mvn verify` (release 21) passes there on a clean checkout, all modules and tests. A build or test run on JDK 25 has not been executed yet; the CI workflow includes one. James 3.9 requires Java 21+, so no dependency forces a lower target.

## Amendment (2026-10-31): Java 21 target

The project owner approved accepting Java 21 for building, because the cloud development environment has only JDK 21. The target was originally Java 25 with source restricted to the Java 21 level, and every build in practice ran with `-Djava.release=21`. Making 21 the default removes that override; no code changed.

## Consequences

- `mvn verify` is the build command on JDK 21 and JDK 25.
- The Docker image builds with a pinned JDK 25 and runs on a JRE 25 (release-21 bytecode).
- Moving the target to 25 later is a one-property change that needs another amendment to this ADR and a JDK 25 CI run first.
