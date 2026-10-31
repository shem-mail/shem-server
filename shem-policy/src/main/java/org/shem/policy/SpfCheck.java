package org.shem.policy;

import org.apache.james.jspf.executor.SPFResult;
import org.apache.james.jspf.impl.SPF;

/**
 * SPF (RFC 7208) through jSPF over Shem's resolver. jSPF enforces the ten-lookup processing limit
 * ({@code SPFSession.MAX_DEPTH}); the resolver bounds each query's time.
 */
final class SpfCheck {
  /** Result for the MAIL FROM identity, or the HELO identity for the null sender. */
  record Outcome(AuthResult result, String identity, String domain) {}

  private final DnsResolver resolver;

  SpfCheck(DnsResolver resolver) {
    this.resolver = resolver;
  }

  Outcome check(String clientAddress, String mailFrom, String helo) {
    boolean nullSender = mailFrom.isEmpty();
    String domain = nullSender ? helo : mailFrom.substring(mailFrom.lastIndexOf('@') + 1);
    // A fresh SPF per check: jSPF's parser and term objects are not documented as thread-safe.
    SPF spf = new SPF(new JspfDns(resolver));
    spf.setUseBestGuess(false);
    SPFResult result;
    try {
      result = spf.checkSPF(clientAddress, nullSender ? "" : mailFrom, helo);
    } catch (RuntimeException e) {
      return new Outcome(AuthResult.PERMERROR, nullSender ? "helo" : "mailfrom", domain);
    }
    return new Outcome(parse(result.getResult()), nullSender ? "helo" : "mailfrom", domain);
  }

  static AuthResult parse(String value) {
    return switch (value) {
      case "pass" -> AuthResult.PASS;
      case "fail" -> AuthResult.FAIL;
      case "softfail" -> AuthResult.SOFTFAIL;
      case "neutral" -> AuthResult.NEUTRAL;
      case "none" -> AuthResult.NONE;
      case "temperror" -> AuthResult.TEMPERROR;
      default -> AuthResult.PERMERROR;
    };
  }
}
