package org.shem.policy;

import java.io.IOException;
import java.io.InputStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;
import org.apache.james.mime4j.dom.address.Address;
import org.apache.james.mime4j.dom.address.AddressList;
import org.apache.james.mime4j.dom.address.Group;
import org.apache.james.mime4j.dom.address.Mailbox;
import org.apache.james.mime4j.field.address.DefaultAddressParser;
import org.apache.james.mime4j.field.address.ParseException;
import org.jspecify.annotations.Nullable;

/**
 * Receipt-time policy for one inbound message: SPF, DKIM, DMARC, optional DNS block lists, built-in
 * protocol checks, content rules, and attachment checks. It returns a {@link Verdict} with the
 * action and the trace fields to prepend. Spam scores only route to Junk; rejection is reserved for
 * DMARC {@code p=reject} failures and dangerous attachments, each by explicit setting. Runs while
 * the recipient mailboxes are locked; private per-user rules are not applied (ADR 0010).
 */
public final class InboundPolicy {
  /** GTUBE (Generic Test for Unsolicited Bulk Email), the standard spam test string. */
  static final String GTUBE =
      "XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X";

  private static final Pattern TOKEN = Pattern.compile("[A-Za-z0-9._@+-]{1,253}");

  /** What to do with a message that matches a reject-capable check. */
  public enum Enforcement {
    REJECT,
    JUNK,
    TAG
  }

  /**
   * Policy settings.
   *
   * @param authservId this server's authentication service identifier (its host name)
   * @param junkScore content score at or above which mail goes to Junk
   * @param dmarcReject handling of DMARC failures whose domain publishes {@code p=reject}
   * @param dangerousAttachments handling of messages with dangerous attachments
   * @param blocklistZones DNS block lists to query with the client address (none by default)
   */
  public record Settings(
      String authservId,
      double junkScore,
      Enforcement dmarcReject,
      Enforcement dangerousAttachments,
      List<String> blocklistZones) {
    public Settings {
      blocklistZones = List.copyOf(blocklistZones);
      if (!TOKEN.matcher(authservId).matches()) {
        throw new IllegalArgumentException("invalid authserv-id");
      }
    }
  }

  /** SMTP envelope facts. */
  public record Envelope(InetAddress client, String helo, String mailFrom) {}

  public enum Action {
    DELIVER,
    JUNK,
    REJECT,
    TEMPFAIL
  }

  /**
   * The decision for one message.
   *
   * @param reply SMTP reply text (code, enhanced status, text) for REJECT and TEMPFAIL
   * @param fields header fields to prepend, without line terminators
   * @param tags reason codes recorded in the encrypted receipt
   */
  public record Verdict(Action action, String reply, List<String> fields, List<String> tags) {
    public Verdict {
      fields = List.copyOf(fields);
      tags = List.copyOf(tags);
    }
  }

  private final Settings settings;
  private final DnsResolver resolver;
  private final SpfCheck spf;
  private final DkimCheck dkim;
  private final Dmarc dmarc;
  private final AtomicReference<RuleSet> rules = new AtomicReference<>(RuleSet.empty());

  public InboundPolicy(Settings settings, DnsResolver resolver, SecureRandom random) {
    this.settings = settings;
    this.resolver = resolver;
    this.spf = new SpfCheck(resolver);
    this.dkim = new DkimCheck(resolver);
    this.dmarc = new Dmarc(resolver, () -> random.nextInt(100));
  }

  /** Atomically replaces the content rules; callers validate with {@link RuleSet#parse} first. */
  public void replaceRules(RuleSet next) {
    rules.set(next);
  }

  public int ruleCount() {
    return rules.get().size();
  }

  /**
   * Whether an existing header field must be removed before storage: authentication results and
   * spam verdicts claiming this server's authority cannot come from the sender.
   */
  public boolean untrusted(String field) {
    if (HeaderRewriter.named(field, "authentication-results")) {
      String value = field.substring(field.indexOf(':') + 1).strip();
      int end = value.indexOf(';');
      String id =
          com.google.common.base.Splitter.on(java.util.regex.Pattern.compile("\\s+"))
              .splitToList((end < 0 ? value : value.substring(0, end)).strip())
              .getFirst();
      return id.equalsIgnoreCase(settings.authservId());
    }
    return HeaderRewriter.named(field, "x-spam-flag")
        || HeaderRewriter.named(field, "x-spam-status")
        || HeaderRewriter.named(field, "x-shem-attachment");
  }

  public Verdict evaluate(Envelope envelope, MessageInput message) throws IOException {
    String client = envelope.client().getHostAddress();
    SpfCheck.Outcome spfResult = spf.check(client, envelope.mailFrom(), envelope.helo());
    HeaderBlock headers;
    List<DkimCheck.Outcome> dkimResults;
    try (InputStream in = message.open()) {
      headers = HeaderBlock.read(in);
      dkimResults = headers.complete() ? dkim.verify(headers, in) : List.of();
    }
    String fromDomain = fromDomain(headers);
    Dmarc.Outcome dmarcResult =
        fromDomain == null
            ? new Dmarc.Outcome(AuthResult.PERMERROR, Dmarc.Disposition.NONE, "", null)
            : dmarc.evaluate(fromDomain, spfResult, dkimResults);
    MessageScan.Result scan;
    try (InputStream in = message.open()) {
      scan = MessageScan.scan(in);
    }

    List<String> hits = new ArrayList<>();
    double score = builtInScore(headers, scan, spfResult, dkimResults, fromDomain, hits);
    score += blocklists(envelope.client(), hits);
    score +=
        rules
            .get()
            .apply(
                scan.headerText().toUpperCase(Locale.ROOT),
                scan.bodyText().toUpperCase(Locale.ROOT),
                hits);
    List<String> attachmentFindings = AttachmentCheck.findings(scan.attachments());

    List<String> tags = new ArrayList<>();
    List<String> fields = new ArrayList<>();
    fields.add(authenticationResults(spfResult, dkimResults, dmarcResult));
    boolean spam = score >= settings.junkScore();
    fields.add("X-Spam-Flag: " + (spam ? "YES" : "NO"));
    fields.add(
        "X-Spam-Status: "
            + (spam ? "Yes" : "No")
            + ", score="
            + String.format(Locale.ROOT, "%.1f", score)
            + " required="
            + String.format(Locale.ROOT, "%.1f", settings.junkScore())
            + (hits.isEmpty() ? "" : " tests=" + String.join(",", hits)));
    if (!attachmentFindings.isEmpty()) {
      fields.add("X-Shem-Attachment: " + String.join(",", attachmentFindings));
    }

    boolean temporary =
        spfResult.result() == AuthResult.TEMPERROR
            || dkimResults.stream().anyMatch(d -> d.result() == AuthResult.TEMPERROR);
    if (dmarcResult.result() == AuthResult.TEMPERROR) {
      return new Verdict(
          Action.TEMPFAIL,
          "451 4.7.0 DMARC policy lookup failed, try again later",
          fields,
          List.of("dmarc-temperror"));
    }
    Action action = Action.DELIVER;
    String reply = "";
    if (dmarcResult.result() == AuthResult.FAIL) {
      tags.add("dmarc-fail");
      if (dmarcResult.disposition() == Dmarc.Disposition.REJECT) {
        if (temporary) {
          return new Verdict(
              Action.TEMPFAIL,
              "451 4.7.0 Authentication lookup failed, try again later",
              fields,
              List.of("dmarc-fail", "auth-temperror"));
        }
        switch (settings.dmarcReject()) {
          case REJECT -> {
            action = Action.REJECT;
            reply = "550 5.7.1 Message rejected by the sender domain's DMARC policy";
          }
          case JUNK -> action = Action.JUNK;
          case TAG -> {}
        }
      } else if (dmarcResult.disposition() == Dmarc.Disposition.QUARANTINE) {
        action = Action.JUNK;
      }
    }
    if (!attachmentFindings.isEmpty() && action != Action.REJECT) {
      tags.add("dangerous-attachment");
      switch (settings.dangerousAttachments()) {
        case REJECT -> {
          action = Action.REJECT;
          reply = "550 5.7.1 Message contains a prohibited attachment type";
        }
        case JUNK -> action = Action.JUNK;
        case TAG -> {}
      }
    }
    if (spam) {
      tags.add("spam");
      if (action == Action.DELIVER) {
        action = Action.JUNK;
      }
    }
    return new Verdict(action, reply, fields, tags);
  }

  private static double builtInScore(
      HeaderBlock headers,
      MessageScan.Result scan,
      SpfCheck.Outcome spf,
      List<DkimCheck.Outcome> dkim,
      @Nullable String fromDomain,
      List<String> hits) {
    double score = 0;
    if (scan.bodyText().contains(GTUBE)) {
      hits.add("GTUBE");
      score += 1000;
    }
    if (spf.result() == AuthResult.FAIL) {
      hits.add("SPF_FAIL");
      score += 3;
    } else if (spf.result() == AuthResult.SOFTFAIL) {
      hits.add("SPF_SOFTFAIL");
      score += 1;
    }
    if (!dkim.isEmpty() && dkim.stream().noneMatch(d -> d.result() == AuthResult.PASS)) {
      hits.add("DKIM_INVALID");
      score += 1;
    }
    if (fromDomain == null) {
      hits.add("FROM_INVALID");
      score += 2;
    }
    if (headers.values("Date").isEmpty()) {
      hits.add("MISSING_DATE");
      score += 1;
    }
    if (headers.values("Message-ID").isEmpty()) {
      hits.add("MISSING_MESSAGE_ID");
      score += 1;
    }
    if (!headers.complete() || scan.malformed()) {
      hits.add("MIME_MALFORMED");
      score += 2;
    }
    return score;
  }

  private double blocklists(InetAddress client, List<String> hits) {
    double score = 0;
    for (String zone : settings.blocklistZones()) {
      try {
        if (!resolver.lookup(reversed(client) + "." + zone, DnsResolver.Type.A).isEmpty()) {
          hits.add("BLOCKLISTED");
          score += 3;
          break;
        }
      } catch (DnsResolver.DnsTemporaryException e) {
        // An unavailable list contributes nothing.
      }
    }
    return score;
  }

  static String reversed(InetAddress address) {
    byte[] bytes = address.getAddress();
    StringBuilder name = new StringBuilder();
    if (address instanceof Inet4Address) {
      for (int i = bytes.length - 1; i >= 0; i--) {
        name.append(bytes[i] & 0xff).append(i == 0 ? "" : ".");
      }
    } else {
      for (int i = bytes.length - 1; i >= 0; i--) {
        name.append(Character.forDigit(bytes[i] & 0xf, 16)).append('.');
        name.append(Character.forDigit((bytes[i] >> 4) & 0xf, 16)).append(i == 0 ? "" : ".");
      }
    }
    return name.toString();
  }

  /** The single RFC5322.From domain, or {@code null} if there is not exactly one author. */
  static @Nullable String fromDomain(HeaderBlock headers) {
    List<String> from = headers.values("From");
    if (from.size() != 1) {
      return null;
    }
    List<Mailbox> mailboxes = new ArrayList<>();
    try {
      AddressList list = DefaultAddressParser.DEFAULT.parseAddressList(from.getFirst());
      for (Address address : list) {
        if (address instanceof Mailbox mailbox) {
          mailboxes.add(mailbox);
        } else if (address instanceof Group group) {
          mailboxes.addAll(group.getMailboxes());
        }
      }
    } catch (ParseException | RuntimeException e) {
      return null;
    }
    if (mailboxes.size() != 1 || mailboxes.getFirst().getDomain() == null) {
      return null;
    }
    String domain = mailboxes.getFirst().getDomain().toLowerCase(Locale.ROOT);
    return TOKEN.matcher(domain).matches() ? domain : null;
  }

  private String authenticationResults(
      SpfCheck.Outcome spf, List<DkimCheck.Outcome> dkim, Dmarc.Outcome dmarc) {
    StringBuilder value =
        new StringBuilder("Authentication-Results: ").append(settings.authservId());
    value
        .append(";\r\n\tspf=")
        .append(spf.result().token())
        .append(spf.identity().equals("helo") ? " smtp.helo=" : " smtp.mailfrom=")
        .append(token(spf.domain()));
    if (dkim.isEmpty()) {
      value.append(";\r\n\tdkim=none");
    }
    for (DkimCheck.Outcome d : dkim) {
      value.append(";\r\n\tdkim=").append(d.result().token());
      if (!d.domain().isEmpty()) {
        value.append(" header.d=").append(token(d.domain()));
      }
      if (!d.selector().isEmpty()) {
        value.append(" header.s=").append(token(d.selector()));
      }
    }
    value.append(";\r\n\tdmarc=").append(dmarc.result().token());
    if (dmarc.policy() != null) {
      value.append(" (p=").append(dmarc.policy()).append(')');
    }
    if (!dmarc.fromDomain().isEmpty()) {
      value.append(" header.from=").append(token(dmarc.fromDomain()));
    }
    return value.toString();
  }

  /** Sender-controlled values are reduced to a safe token so they cannot inject header syntax. */
  private static String token(String value) {
    return TOKEN.matcher(value).matches() ? value : "invalid";
  }
}
