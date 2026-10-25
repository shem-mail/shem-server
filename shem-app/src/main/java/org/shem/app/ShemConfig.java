package org.shem.app;

import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;
import org.shem.crypto.Argon2Parameters;

/**
 * Typed, validated runtime configuration loaded from a properties file. Unknown keys and invalid
 * values fail startup. The file must never contain user passwords; server-wide secrets live in
 * separate service-account-only files referenced by path.
 */
public record ShemConfig(
    Path dataDirectory,
    Mode mode,
    boolean devBootstrapEnabled,
    Argon2Parameters slotParameters,
    int kdfBudgetKiB,
    Duration kdfMaxWait,
    long maxMessageBytes,
    Duration bootstrapValidity,
    Duration recreationWaitingPeriod,
    Duration oldKeyRetention,
    boolean acceptMailBeforeEnrollment) {

  /** Deployment mode; production refuses development-only features. */
  public enum Mode {
    DEVELOPMENT,
    PRODUCTION
  }

  private static final Set<String> KEYS =
      Set.of(
          "data.directory",
          "mode",
          "dev.bootstrap.enabled",
          "argon2.memoryKiB",
          "argon2.iterations",
          "argon2.parallelism",
          "kdf.budgetKiB",
          "kdf.maxWait",
          "message.maxBytes",
          "account.bootstrapValidity",
          "account.recreationWaitingPeriod",
          "keys.oldKeyRetention",
          "delivery.acceptBeforeEnrollment");

  public ShemConfig {
    if (mode == Mode.PRODUCTION && devBootstrapEnabled) {
      throw new IllegalArgumentException("dev.bootstrap.enabled is not allowed in production mode");
    }
    if (!Argon2Parameters.Limits.DEFAULT.accepts(slotParameters)) {
      throw new IllegalArgumentException("argon2 parameters outside accepted bounds");
    }
    if (kdfBudgetKiB < slotParameters.memoryKiB()) {
      throw new IllegalArgumentException("kdf.budgetKiB must admit at least one derivation");
    }
    if (maxMessageBytes < 1024 || maxMessageBytes > 512L * 1024 * 1024) {
      throw new IllegalArgumentException("message.maxBytes out of range");
    }
  }

  public static ShemConfig load(Path file) throws IOException {
    Properties properties = new Properties();
    try (Reader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
      properties.load(reader);
    }
    Path base = file.toAbsolutePath().getParent();
    return fromProperties(properties, base == null ? Path.of("/") : base);
  }

  static ShemConfig fromProperties(Properties p, Path base) {
    Set<String> unknown = new HashSet<>(p.stringPropertyNames());
    unknown.removeAll(KEYS);
    if (!unknown.isEmpty()) {
      throw new IllegalArgumentException("unknown configuration keys: " + unknown);
    }
    String dataDir = p.getProperty("data.directory");
    if (dataDir == null || dataDir.isBlank()) {
      throw new IllegalArgumentException("data.directory is required");
    }
    return new ShemConfig(
        base.resolve(dataDir).normalize(),
        Mode.valueOf(p.getProperty("mode", "PRODUCTION").trim().toUpperCase(java.util.Locale.ROOT)),
        bool(p, "dev.bootstrap.enabled", false),
        new Argon2Parameters(
            integer(p, "argon2.memoryKiB", Argon2Parameters.DEFAULT.memoryKiB()),
            integer(p, "argon2.iterations", Argon2Parameters.DEFAULT.iterations()),
            integer(p, "argon2.parallelism", Argon2Parameters.DEFAULT.parallelism())),
        integer(p, "kdf.budgetKiB", 4 * Argon2Parameters.DEFAULT.memoryKiB()),
        duration(p, "kdf.maxWait", Duration.ofSeconds(2)),
        Long.parseLong(p.getProperty("message.maxBytes", String.valueOf(50L * 1024 * 1024)).trim()),
        duration(p, "account.bootstrapValidity", Duration.ofDays(3)),
        duration(p, "account.recreationWaitingPeriod", Duration.ofDays(30)),
        duration(p, "keys.oldKeyRetention", Duration.ofMinutes(15)),
        bool(p, "delivery.acceptBeforeEnrollment", true));
  }

  private static boolean bool(Properties p, String key, boolean fallback) {
    String value = p.getProperty(key);
    if (value == null) {
      return fallback;
    }
    return switch (value.trim()) {
      case "true" -> true;
      case "false" -> false;
      default -> throw new IllegalArgumentException(key + " must be true or false");
    };
  }

  private static int integer(Properties p, String key, int fallback) {
    String value = p.getProperty(key);
    try {
      return value == null ? fallback : Integer.parseInt(value.trim());
    } catch (NumberFormatException e) {
      throw new IllegalArgumentException(key + " must be an integer", e);
    }
  }

  /** ISO-8601 durations such as {@code PT15M} or {@code P3D}. */
  private static Duration duration(Properties p, String key, Duration fallback) {
    String value = p.getProperty(key);
    try {
      return value == null ? fallback : Duration.parse(value.trim());
    } catch (java.time.format.DateTimeParseException e) {
      throw new IllegalArgumentException(key + " must be an ISO-8601 duration", e);
    }
  }
}
