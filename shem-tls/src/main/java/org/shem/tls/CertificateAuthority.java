package org.shem.tls;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.List;

/** Issues a certificate for host names, proving control through HTTP-01 (ADR 0018). */
public interface CertificateAuthority {
  /**
   * Orders and downloads a certificate for {@code hosts} bound to {@code domainKey}, publishing
   * HTTP-01 tokens in {@code challenges} while the order is validated and withdrawing them after.
   *
   * @return the leaf certificate followed by its issuers
   */
  List<X509Certificate> issue(List<String> hosts, KeyPair domainKey, Http01Challenges challenges)
      throws Exception;
}
