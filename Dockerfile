# syntax=docker/dockerfile:1

# Base images are pinned by multi-arch index digest; update tag and digest together.
FROM maven:3.9.16-eclipse-temurin-25-noble@sha256:93b8a14ea2f412782e4e842651273b4d903e35cc496284f178fbbe2d67d00976 AS build
WORKDIR /src
COPY .mvn/ .mvn/
COPY pom.xml ./
COPY shem-app/pom.xml shem-app/
RUN --mount=type=cache,target=/root/.m2 mvn dependency:go-offline
COPY shem-app/src/ shem-app/src/
RUN --mount=type=cache,target=/root/.m2 mvn verify

FROM eclipse-temurin:25.0.4.1_1-jre-noble@sha256:3f2223fe04b750aa5a8179e29b5c9a1ddf7665fc9bb08bfe11ad01d143bc13a5
RUN groupadd --system shem && useradd --system --gid shem --no-create-home --shell /usr/sbin/nologin shem
WORKDIR /opt/shem
COPY --from=build /src/shem-app/target/lib/ lib/
COPY --from=build /src/shem-app/target/shem-app.jar shem-app.jar
COPY --from=build /src/shem-app/target/bom.json sbom/shem-app.cdx.json
USER shem:shem
# No heap/core dumps and no attach API: unlocked keys and plaintext live in process memory.
# Core-dump limits (ulimit -c 0) and protected swap/tmpfs are still host/runtime settings.
ENTRYPOINT ["java", "-XX:-HeapDumpOnOutOfMemoryError", "-XX:-CreateCoredumpOnCrash", "-XX:+DisableAttachMechanism", "-XX:+ExitOnOutOfMemoryError", "-jar", "/opt/shem/shem-app.jar"]
