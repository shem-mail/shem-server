package org.shem.policy;

import com.google.common.net.InternetDomainName;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.IntSupplier;
import org.jspecify.annotations.Nullable;

/**
 * DMARC (RFC 7489) policy discovery and identifier alignment. No maintained Java DMARC library
 * exists, so this small evaluator is Shem's own (ADR 0010); it reuses SPF and DKIM results from
 * jSPF and jDKIM and the public suffix list bundled with Guava. Aggregate and failure reports
 * ({@code rua}/{@code ruf}) are not sent.
 */
final class Dmarc {
  /** What the domain owner asks receivers to do with failing mail. */
  enum Disposition {
    NONE,
    QUARANTINE,
    REJECT
  }

  /**
   * Evaluation result. {@code disposition} is the policy to apply after {@code pct} sampling; it is
   * {@link Disposition#NONE} unless the result is {@link AuthResult#FAIL}.
   */
  record Outcome(
      AuthResult result, Disposition disposition, String fromDomain, @Nullable String policy) {}

  /** A parsed {@code v=DMARC1} record. */
  record Policy(Disposition p, Disposition sp, boolean strictDkim, boolean strictSpf, int pct) {}

  private final DnsResolver resolver;
  private final IntSupplier percentile;

  /** {@code percentile} returns a uniform value in [0, 100) for {@code pct} sampling. */
  Dmarc(DnsResolver resolver, IntSupplier percentile) {
    this.resolver = resolver;
    this.percentile = percentile;
  }

  Outcome evaluate(String fromDomain, SpfCheck.Outcome spf, List<DkimCheck.Outcome> dkim) {
    String from = fromDomain.toLowerCase(Locale.ROOT);
    String organization = organizationalDomain(from);
    Policy policy;
    boolean inherited = false;
    try {
      policy = discover(from);
      if (policy == null && !organization.equals(from)) {
        policy = discover(organization);
        inherited = policy != null;
      }
    } catch (DnsResolver.DnsTemporaryException e) {
      return new Outcome(AuthResult.TEMPERROR, Disposition.NONE, from, null);
    }
    if (policy == null) {
      return new Outcome(AuthResult.NONE, Disposition.NONE, from, null);
    }
    return apply(policy, inherited, from, spf, dkim);
  }

  private Outcome apply(
      Policy policy,
      boolean inherited,
      String from,
      SpfCheck.Outcome spf,
      List<DkimCheck.Outcome> dkim) {
    boolean dkimAligned =
        dkim.stream()
            .anyMatch(
                d ->
                    d.result() == AuthResult.PASS
                        && aligned(d.domain(), from, policy.strictDkim()));
    boolean spfAligned =
        spf.result() == AuthResult.PASS
            && spf.identity().equals("mailfrom")
            && aligned(spf.domain(), from, policy.strictSpf());
    Disposition requested = inherited ? policy.sp() : policy.p();
    String label = requested.name().toLowerCase(Locale.ROOT);
    if (dkimAligned || spfAligned) {
      return new Outcome(AuthResult.PASS, Disposition.NONE, from, label);
    }
    Disposition applied = requested;
    if (policy.pct() < 100 && percentile.getAsInt() >= policy.pct()) {
      // RFC 7489 section 6.6.4: outside the sample, apply the next less strict policy.
      applied = requested == Disposition.REJECT ? Disposition.QUARANTINE : Disposition.NONE;
    }
    return new Outcome(AuthResult.FAIL, applied, from, label);
  }

  private @Nullable Policy discover(String domain) throws DnsResolver.DnsTemporaryException {
    Policy found = null;
    for (String record : resolver.lookup("_dmarc." + domain, DnsResolver.Type.TXT)) {
      Policy parsed = parse(record);
      if (parsed != null) {
        if (found != null) {
          return null; // more than one DMARC record: none applies (RFC 7489 section 6.6.3)
        }
        found = parsed;
      }
    }
    return found;
  }

  /** Parses a DMARC record; {@code null} if it is not a valid {@code v=DMARC1} record. */
  static @Nullable Policy parse(String record) {
    Map<String, String> tags = new HashMap<>();
    List<String> parts = com.google.common.base.Splitter.on(';').splitToList(record);
    for (int i = 0; i < parts.size(); i++) {
      String part = parts.get(i).trim();
      if (part.isEmpty()) {
        continue;
      }
      int eq = part.indexOf('=');
      if (eq <= 0) {
        return null;
      }
      String name = part.substring(0, eq).trim().toLowerCase(Locale.ROOT);
      String value = part.substring(eq + 1).trim();
      if (i == 0 && !(name.equals("v") && value.equals("DMARC1"))) {
        return null;
      }
      tags.putIfAbsent(name, value);
    }
    if (!tags.containsKey("v")) {
      return null;
    }
    Disposition p = disposition(tags.get("p"));
    if (p == null) {
      // An invalid or missing p= with a reporting address is treated as p=none (6.6.3).
      if (!tags.containsKey("rua")) {
        return null;
      }
      p = Disposition.NONE;
    }
    Disposition sp = tags.containsKey("sp") ? disposition(tags.get("sp")) : p;
    int pct = 100;
    if (tags.containsKey("pct")) {
      try {
        pct = Math.max(0, Math.min(100, Integer.parseInt(tags.get("pct"))));
      } catch (NumberFormatException e) {
        pct = 100;
      }
    }
    return new Policy(
        p,
        sp == null ? p : sp,
        "s".equalsIgnoreCase(tags.get("adkim")),
        "s".equalsIgnoreCase(tags.get("aspf")),
        pct);
  }

  private static @Nullable Disposition disposition(@Nullable String value) {
    if (value == null) {
      return null;
    }
    return switch (value.toLowerCase(Locale.ROOT)) {
      case "none" -> Disposition.NONE;
      case "quarantine" -> Disposition.QUARANTINE;
      case "reject" -> Disposition.REJECT;
      default -> null;
    };
  }

  static boolean aligned(String identifier, String from, boolean strict) {
    String id = identifier.toLowerCase(Locale.ROOT);
    if (id.isEmpty()) {
      return false;
    }
    return strict ? id.equals(from) : organizationalDomain(id).equals(organizationalDomain(from));
  }

  /** The registered domain below the public suffix, or the name itself if none is known. */
  static String organizationalDomain(String domain) {
    try {
      InternetDomainName name = InternetDomainName.from(domain);
      return name.isUnderPublicSuffix() ? name.topPrivateDomain().toString() : domain;
    } catch (IllegalArgumentException | IllegalStateException e) {
      return domain;
    }
  }
}
