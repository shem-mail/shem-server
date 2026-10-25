package org.shem.identity;

import java.net.IDN;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Canonical mailbox address: lowercase dot-atom local part and lowercase ASCII (IDNA) domain.
 * Quoted local parts and address literals are not accepted for local accounts.
 */
public record EmailAddress(String localPart, String domain) {
  private static final Pattern ATOM = Pattern.compile("[a-z0-9!#$%&'*+/=?^_`{|}~-]+");
  private static final Pattern LABEL = Pattern.compile("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?");

  public EmailAddress {
    if (!isValidLocalPart(localPart) || !isValidDomain(domain)) {
      throw new IllegalArgumentException("invalid address");
    }
  }

  /** Parses and canonicalizes; throws {@link IllegalArgumentException} for invalid input. */
  public static EmailAddress parse(String address) {
    int at = address.lastIndexOf('@');
    if (at <= 0 || at == address.length() - 1 || address.length() > 320) {
      throw new IllegalArgumentException("invalid address");
    }
    return new EmailAddress(
        address.substring(0, at).toLowerCase(Locale.ROOT),
        canonicalDomain(address.substring(at + 1)));
  }

  public static String canonicalDomain(String domain) {
    String trimmed = domain.endsWith(".") ? domain.substring(0, domain.length() - 1) : domain;
    try {
      String ascii = IDN.toASCII(trimmed, IDN.USE_STD3_ASCII_RULES).toLowerCase(Locale.ROOT);
      if (!isValidDomain(ascii)) {
        throw new IllegalArgumentException("invalid domain");
      }
      return ascii;
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException("invalid domain", e);
    }
  }

  private static boolean isValidLocalPart(String localPart) {
    if (localPart.isEmpty() || localPart.length() > 64) {
      return false;
    }
    if (localPart.startsWith(".") || localPart.endsWith(".") || localPart.contains("..")) {
      return false;
    }
    for (String atom : localPart.split("\\.", -1)) {
      if (!ATOM.matcher(atom).matches()) {
        return false;
      }
    }
    return true;
  }

  private static boolean isValidDomain(String domain) {
    if (domain.isEmpty() || domain.length() > 253 || !domain.contains(".")) {
      return false;
    }
    for (String label : domain.split("\\.", -1)) {
      if (!LABEL.matcher(label).matches()) {
        return false;
      }
    }
    return true;
  }

  @Override
  public String toString() {
    return localPart + "@" + domain;
  }
}
