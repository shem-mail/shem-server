package org.shem.app;

import java.io.IOException;
import java.io.Reader;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import org.jspecify.annotations.Nullable;
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
    boolean acceptMailBeforeEnrollment,
    @Nullable Tls tls,
    @Nullable Imap imap,
    @Nullable Smtp smtp) {

  /** Listener certificate files (PEM) and the host names they must cover. */
  public record Tls(Path certificateChain, Path privateKey, List<String> hostNames) {
    public Tls {
      hostNames = List.copyOf(hostNames);
      if (hostNames.isEmpty()) {
        throw new IllegalArgumentException("tls.hostNames must list at least one host");
      }
    }
  }

  /** IMAP listener (implicit TLS). */
  public record Imap(InetSocketAddress bind, int maxConnections, int maxConnectionsPerIp) {}

  /** Inbound MX listener (port 25, opportunistic STARTTLS). */
  public record Smtp(
      InetSocketAddress bind,
      int maxConnections,
      int maxConnectionsPerIp,
      int maxRecipients,
      int maxUnknownRecipients) {
    public Smtp {
      if (maxConnections <= 0 || maxConnectionsPerIp <= 0 || maxRecipients <= 0) {
        throw new IllegalArgumentException("smtp limits must be positive");
      }
      if (maxUnknownRecipients < 0) {
        throw new IllegalArgumentException("smtp.maxUnknownRecipients must not be negative");
      }
    }
  }

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
          "delivery.acceptBeforeEnrollment",
          "tls.certificateChain",
          "tls.privateKey",
          "tls.hostNames",
          "imap.bind",
          "imap.maxConnections",
          "imap.maxConnectionsPerIp",
          "smtp.bind",
          "smtp.maxConnections",
          "smtp.maxConnectionsPerIp",
          "smtp.maxRecipients",
          "smtp.maxUnknownRecipients");

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
    if (imap != null && tls == null) {
      throw new IllegalArgumentException(
          "imap requires tls: credentials are never accepted without TLS");
    }
    if (smtp != null && tls == null) {
      throw new IllegalArgumentException("smtp requires tls: STARTTLS is always offered");
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
        bool(p, "delivery.acceptBeforeEnrollment", true),
        tls(p, base),
        imap(p),
        smtp(p));
  }

  private static @Nullable Tls tls(Properties p, Path base) {
    String chain = p.getProperty("tls.certificateChain");
    String key = p.getProperty("tls.privateKey");
    if (chain == null && key == null) {
      return null;
    }
    if (chain == null || key == null) {
      throw new IllegalArgumentException("tls.certificateChain and tls.privateKey go together");
    }
    List<String> hosts =
        Arrays.stream(p.getProperty("tls.hostNames", "").split(","))
            .map(String::trim)
            .filter(h -> !h.isEmpty())
            .toList();
    return new Tls(base.resolve(chain.trim()), base.resolve(key.trim()), hosts);
  }

  private static @Nullable Imap imap(Properties p) {
    String bind = p.getProperty("imap.bind");
    if (bind == null) {
      return null;
    }
    return new Imap(
        address(bind, "imap.bind"),
        integer(p, "imap.maxConnections", 500),
        integer(p, "imap.maxConnectionsPerIp", 20));
  }

  private static @Nullable Smtp smtp(Properties p) {
    String bind = p.getProperty("smtp.bind");
    if (bind == null) {
      return null;
    }
    return new Smtp(
        address(bind, "smtp.bind"),
        integer(p, "smtp.maxConnections", 200),
        integer(p, "smtp.maxConnectionsPerIp", 10),
        integer(p, "smtp.maxRecipients", 100),
        integer(p, "smtp.maxUnknownRecipients", 5));
  }

  /** {@code host:port}; IPv6 literals in brackets. */
  static InetSocketAddress address(String value, String key) {
    String v = value.trim();
    int colon = v.lastIndexOf(':');
    if (colon <= 0 || colon == v.length() - 1) {
      throw new IllegalArgumentException(key + " must be host:port");
    }
    String host = v.substring(0, colon);
    if (host.startsWith("[") && host.endsWith("]")) {
      host = host.substring(1, host.length() - 1);
    }
    int port;
    try {
      port = Integer.parseInt(v.substring(colon + 1));
    } catch (NumberFormatException e) {
      throw new IllegalArgumentException(key + " has an invalid port", e);
    }
    if (port < 1 || port > 65535) {
      throw new IllegalArgumentException(key + " has an invalid port");
    }
    return InetSocketAddress.createUnresolved(host, port);
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
