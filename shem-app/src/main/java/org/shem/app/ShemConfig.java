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
import org.shem.policy.InboundPolicy;

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
    @Nullable Smtp smtp,
    @Nullable Submission submission,
    Policy policy,
    @Nullable Outbound outbound,
    @Nullable Http http,
    @Nullable MtaSts mtaSts) {

  /**
   * Listener certificate files (PEM) and the host names they must cover. With {@code acme}, the
   * files are the live ACME generation under the data directory (ADR 0018).
   */
  public record Tls(
      Path certificateChain, Path privateKey, List<String> hostNames, @Nullable Acme acme) {
    public Tls {
      hostNames = List.copyOf(hostNames);
      if (hostNames.isEmpty()) {
        throw new IllegalArgumentException("tls.hostNames must list at least one host");
      }
    }
  }

  /**
   * Automatic certificates (ADR 0018).
   *
   * @param directory the CA's ACME directory URL
   * @param email optional contact address registered with the CA
   * @param challengeBind the plain-HTTP listener for HTTP-01 and redirects (port 80 in production)
   */
  public record Acme(
      java.net.URI directory, @Nullable String email, InetSocketAddress challengeBind) {
    public Acme {
      if (!directory.getScheme().equals("https")) {
        throw new IllegalArgumentException("acme.directory must be an https URL");
      }
    }
  }

  /** The hosted MTA-STS policy (ADR 0018); {@code mx} is the first TLS host name. */
  public record MtaSts(String mode, Duration maxAge) {
    public MtaSts {
      if (!Set.of("enforce", "testing", "none").contains(mode)) {
        throw new IllegalArgumentException("mtaSts.mode must be enforce, testing, or none");
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

  /**
   * Authenticated submission listeners (ADR 0011).
   *
   * @param implicitTlsBind port 465 listener, if any
   * @param startTlsBind port 587 listener, if any
   */
  public record Submission(
      @Nullable InetSocketAddress implicitTlsBind,
      @Nullable InetSocketAddress startTlsBind,
      int maxConnections,
      int maxConnectionsPerIp,
      int maxRecipients,
      int recipientsPerHour) {
    public Submission {
      if (implicitTlsBind == null && startTlsBind == null) {
        throw new IllegalArgumentException("submission needs implicitTlsBind or startTlsBind");
      }
      if (maxConnections <= 0
          || maxConnectionsPerIp <= 0
          || maxRecipients <= 0
          || recipientsPerHour <= 0) {
        throw new IllegalArgumentException("submission limits must be positive");
      }
    }
  }

  /**
   * HTTPS API listener (ADR 0013).
   *
   * @param origin the browser origin allowed for mutating requests and the WebAuthn relying party;
   *     defaults to {@code https://} plus the first TLS host name
   */
  public record Http(
      InetSocketAddress bind,
      @Nullable String origin,
      Duration idleTimeout,
      Duration absoluteLifetime) {}

  /** Remote delivery of submitted mail through the plaintext outbound queue (ADR 0012). */
  public record Outbound(int maxItems, long maxBytes, Duration lifetime, int maxConcurrent) {
    public Outbound {
      if (maxItems <= 0 || maxBytes <= 0 || maxConcurrent <= 0 || lifetime.isNegative()) {
        throw new IllegalArgumentException("outbound limits must be positive");
      }
    }
  }

  /**
   * Inbound mail policy (ADR 0010).
   *
   * @param dnsServers resolvers to query; empty means the system configuration
   * @param blocklists DNS block list zones; each query reveals the client address to that zone
   */
  public record Policy(
      double junkScore,
      InboundPolicy.Enforcement dmarcReject,
      InboundPolicy.Enforcement dangerousAttachments,
      boolean greylist,
      @Nullable Path rulesFile,
      List<String> blocklists,
      List<String> dnsServers,
      Duration dnsTimeout) {
    public Policy {
      blocklists = List.copyOf(blocklists);
      dnsServers = List.copyOf(dnsServers);
      if (junkScore <= 0 || junkScore > 1000) {
        throw new IllegalArgumentException("policy.junkScore out of range");
      }
      if (dnsTimeout.isNegative() || dnsTimeout.isZero() || dnsTimeout.toSeconds() > 30) {
        throw new IllegalArgumentException("dns.timeout must be between 1ms and 30s");
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
          "acme.directory",
          "acme.email",
          "acme.agreeToTerms",
          "acme.challengeBind",
          "mtaSts.mode",
          "mtaSts.maxAge",
          "imap.bind",
          "imap.maxConnections",
          "imap.maxConnectionsPerIp",
          "smtp.bind",
          "smtp.maxConnections",
          "smtp.maxConnectionsPerIp",
          "smtp.maxRecipients",
          "smtp.maxUnknownRecipients",
          "submission.implicitTlsBind",
          "submission.startTlsBind",
          "submission.maxConnections",
          "submission.maxConnectionsPerIp",
          "submission.maxRecipients",
          "submission.recipientsPerHour",
          "http.bind",
          "http.origin",
          "http.idleTimeout",
          "http.absoluteLifetime",
          "outbound.enabled",
          "outbound.maxItems",
          "outbound.maxBytes",
          "outbound.lifetime",
          "outbound.maxConcurrent",
          "policy.junkScore",
          "policy.dmarcReject",
          "policy.dangerousAttachments",
          "policy.greylist",
          "policy.rulesFile",
          "policy.blocklists",
          "dns.servers",
          "dns.timeout");

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
    if (submission != null && tls == null) {
      throw new IllegalArgumentException(
          "submission requires tls: credentials are never accepted without TLS");
    }
    if (http != null && tls == null) {
      throw new IllegalArgumentException(
          "http requires tls: credentials are never accepted without TLS");
    }
    if (outbound != null && submission == null) {
      throw new IllegalArgumentException("outbound.enabled requires a submission listener");
    }
    if (smtp != null && tls == null) {
      throw new IllegalArgumentException("smtp requires tls: STARTTLS is always offered");
    }
    if (mtaSts != null && http == null) {
      throw new IllegalArgumentException("mtaSts.mode requires the HTTPS listener (http.bind)");
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
    Path data = base.resolve(dataDir).normalize();
    return new ShemConfig(
        data,
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
        tls(p, base, data),
        imap(p),
        smtp(p),
        submission(p),
        policy(p, base),
        outbound(p),
        http(p),
        mtaSts(p));
  }

  private static @Nullable Tls tls(Properties p, Path base, Path data) {
    String chain = p.getProperty("tls.certificateChain");
    String key = p.getProperty("tls.privateKey");
    List<String> hosts =
        Arrays.stream(p.getProperty("tls.hostNames", "").split(","))
            .map(String::trim)
            .filter(h -> !h.isEmpty())
            .map(h -> h.toLowerCase(java.util.Locale.ROOT))
            .toList();
    String directory = p.getProperty("acme.directory");
    if (directory != null) {
      if (chain != null || key != null) {
        throw new IllegalArgumentException(
            "acme.directory manages the certificate; remove tls.certificateChain/privateKey");
      }
      if (!bool(p, "acme.agreeToTerms", false)) {
        throw new IllegalArgumentException(
            "acme.agreeToTerms=true is required: read the CA's terms of service first");
      }
      String bind = p.getProperty("acme.challengeBind");
      if (bind == null) {
        throw new IllegalArgumentException("acme.challengeBind is required (port 80 listener)");
      }
      String email = p.getProperty("acme.email");
      Path live = data.resolve("acme").resolve("live");
      return new Tls(
          live.resolve("chain.pem"),
          live.resolve("key.pem"),
          hosts,
          new Acme(
              java.net.URI.create(directory.strip()),
              email == null || email.isBlank() ? null : email.strip(),
              address(bind, "acme.challengeBind")));
    }
    if (chain == null && key == null) {
      return null;
    }
    if (chain == null || key == null) {
      throw new IllegalArgumentException("tls.certificateChain and tls.privateKey go together");
    }
    return new Tls(base.resolve(chain.trim()), base.resolve(key.trim()), hosts, null);
  }

  private static @Nullable MtaSts mtaSts(Properties p) {
    String mode = p.getProperty("mtaSts.mode");
    if (mode == null) {
      return null;
    }
    return new MtaSts(
        mode.strip().toLowerCase(java.util.Locale.ROOT),
        duration(p, "mtaSts.maxAge", Duration.ofDays(7)));
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

  private static @Nullable Submission submission(Properties p) {
    String implicit = p.getProperty("submission.implicitTlsBind");
    String starttls = p.getProperty("submission.startTlsBind");
    if (implicit == null && starttls == null) {
      return null;
    }
    return new Submission(
        implicit == null ? null : address(implicit, "submission.implicitTlsBind"),
        starttls == null ? null : address(starttls, "submission.startTlsBind"),
        integer(p, "submission.maxConnections", 200),
        integer(p, "submission.maxConnectionsPerIp", 20),
        integer(p, "submission.maxRecipients", 100),
        integer(p, "submission.recipientsPerHour", 500));
  }

  private static @Nullable Http http(Properties p) {
    String bind = p.getProperty("http.bind");
    if (bind == null) {
      return null;
    }
    String origin = p.getProperty("http.origin");
    return new Http(
        address(bind, "http.bind"),
        origin == null || origin.isBlank() ? null : origin.strip(),
        duration(p, "http.idleTimeout", Duration.ofMinutes(30)),
        duration(p, "http.absoluteLifetime", Duration.ofHours(12)));
  }

  private static @Nullable Outbound outbound(Properties p) {
    if (!bool(p, "outbound.enabled", false)) {
      return null;
    }
    long maxBytes;
    try {
      maxBytes =
          Long.parseLong(p.getProperty("outbound.maxBytes", String.valueOf(2L << 30)).trim());
    } catch (NumberFormatException e) {
      throw new IllegalArgumentException("outbound.maxBytes must be an integer", e);
    }
    return new Outbound(
        integer(p, "outbound.maxItems", 10_000),
        maxBytes,
        duration(p, "outbound.lifetime", Duration.ofDays(5)),
        integer(p, "outbound.maxConcurrent", 16));
  }

  private static Policy policy(Properties p, Path base) {
    String rules = p.getProperty("policy.rulesFile");
    double junkScore;
    try {
      junkScore = Double.parseDouble(p.getProperty("policy.junkScore", "5.0").trim());
    } catch (NumberFormatException e) {
      throw new IllegalArgumentException("policy.junkScore must be a number", e);
    }
    return new Policy(
        junkScore,
        enforcement(p, "policy.dmarcReject"),
        enforcement(p, "policy.dangerousAttachments"),
        bool(p, "policy.greylist", true),
        rules == null || rules.isBlank() ? null : base.resolve(rules.trim()).normalize(),
        list(p, "policy.blocklists"),
        list(p, "dns.servers"),
        duration(p, "dns.timeout", Duration.ofSeconds(3)));
  }

  private static InboundPolicy.Enforcement enforcement(Properties p, String key) {
    String value = p.getProperty(key, "REJECT").trim().toUpperCase(java.util.Locale.ROOT);
    try {
      return InboundPolicy.Enforcement.valueOf(value);
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException(key + " must be REJECT, JUNK, or TAG", e);
    }
  }

  private static List<String> list(Properties p, String key) {
    return Arrays.stream(p.getProperty(key, "").split(",", -1))
        .map(String::trim)
        .filter(s -> !s.isEmpty())
        .toList();
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
