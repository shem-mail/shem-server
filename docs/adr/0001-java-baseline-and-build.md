# ADR 0001: Java Baseline and Build

Status: accepted; JDK 25 compilation and test run still pending.

## Decision

- Target Java 25 LTS (`java.release=25` in the parent POM), no preview features.
- Source is written to the Java 21 language and API level so it compiles unchanged on both. Do not use Java 22+ language features (unnamed variables, flexible constructor bodies, module imports) or APIs (stream gatherers, `Console.isTerminal`, PEM API) until JDK 25 CI exists.
- Maven 3.9 multi-module build without a wrapper. Gates in the lifecycle: enforcer (Maven/Java versions, plugin versions, dependency convergence), Error Prone + NullAway (JSpecify mode, `-Werror`), Spotless with google-java-format, Surefire/Failsafe, CycloneDX SBOM for `shem-app`.
- Error Prone on JDK 21 needs `-XDaddTypeAnnotationsToSymbol=true` and the `--add-exports/--add-opens` flags in `.mvn/jvm.config`; both are harmless on JDK 25.

## Evidence

This development environment provides only OpenJDK 21.0.12 and Maven 3.9.11; JDK 25 downloads (Adoptium, java.net, Azul, Corretto) are blocked by the network policy. Every build in this repository so far ran as:

```
mvn -Djava.release=21 verify
```

That command passes on a clean checkout (all modules, all tests). **`mvn verify` with the default release 25 has not been executed.** James 3.9 requires Java 21+, so no dependency forces a lower target.

## Consequences

CI must pin a JDK 25 image (the Dockerfile already does) and run plain `mvn verify`. If JDK 25 turns out to be incompatible with a selected library, switching the target to 21 is a one-property change that needs an amendment to this ADR.
