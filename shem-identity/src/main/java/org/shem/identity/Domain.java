package org.shem.identity;

import java.time.Instant;
import org.jspecify.annotations.Nullable;
import org.shem.common.OpaqueId;

/**
 * A locally hosted mail domain. DKIM selector metadata is public (it is published in DNS); the
 * signing key itself belongs to the submission role.
 */
public record Domain(
    OpaqueId domainId,
    String name,
    Instant createdAt,
    @Nullable String dkimSelector,
    long version) {
  public Domain {
    name = EmailAddress.canonicalDomain(name);
  }

  public Domain withDkimSelector(String selector) {
    return new Domain(domainId, name, createdAt, selector, version + 1);
  }
}
