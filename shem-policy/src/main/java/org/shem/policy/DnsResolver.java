package org.shem.policy;

import java.util.List;

/**
 * DNS lookups used by policy. An empty list means the name or record type does not exist (NXDOMAIN
 * or NODATA); {@link DnsTemporaryException} means the answer is unknown (timeout, SERVFAIL).
 * Implementations bound time per query and cache size. Every query name is visible to the
 * configured resolver (ADR 0010).
 */
public interface DnsResolver {
  enum Type {
    A,
    AAAA,
    MX,
    PTR,
    TXT
  }

  /**
   * Returns the records of {@code type} at {@code name}: addresses as text for A/AAAA, {@code
   * "<preference> <host>"} for MX, host names for PTR, and character strings concatenated per
   * record for TXT. Host names have no trailing dot; the null MX target is {@code "."}.
   */
  List<String> lookup(String name, Type type) throws DnsTemporaryException;

  /** The answer is not known right now. */
  final class DnsTemporaryException extends Exception {
    private static final long serialVersionUID = 1L;

    public DnsTemporaryException(String message) {
      super(message);
    }
  }
}
