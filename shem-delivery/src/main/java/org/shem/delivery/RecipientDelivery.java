package org.shem.delivery;

import java.util.List;
import org.shem.identity.RecipientRoute;
import org.shem.store.DeliveryTarget;

/** Per-recipient delivery instructions; all private fields end up only inside the receipt. */
public record RecipientDelivery(
    RecipientRoute route,
    String recipientAddress,
    DeliveryTarget target,
    int systemFlags,
    List<String> keywords,
    List<String> policyTags) {
  public RecipientDelivery {
    keywords = List.copyOf(keywords);
    policyTags = List.copyOf(policyTags);
  }
}
