package org.shem.policy;

import java.util.Locale;

/** RFC 8601 result values shared by SPF, DKIM, and DMARC. */
public enum AuthResult {
  PASS,
  FAIL,
  SOFTFAIL,
  NEUTRAL,
  NONE,
  TEMPERROR,
  PERMERROR,
  POLICY;

  /** The lower-case token used in {@code Authentication-Results}. */
  public String token() {
    return name().toLowerCase(Locale.ROOT);
  }
}
