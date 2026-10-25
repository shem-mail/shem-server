package org.shem.identity;

import java.util.List;
import org.shem.common.OpaqueId;

/**
 * Local alias. Targets are local addresses (accounts or other aliases); external forwarding is not
 * supported because it would turn the routing directory into a relay. {@code senders} lists the
 * mailboxes allowed to submit mail using this alias as their identity.
 */
public record Alias(
    OpaqueId aliasId,
    EmailAddress address,
    List<EmailAddress> targets,
    List<OpaqueId> senders,
    long version) {
  public static final int MAX_TARGETS = 64;

  public Alias {
    targets = List.copyOf(targets);
    senders = List.copyOf(senders);
    if (targets.isEmpty() || targets.size() > MAX_TARGETS || senders.size() > MAX_TARGETS) {
      throw new IllegalArgumentException("invalid alias target count");
    }
  }
}
