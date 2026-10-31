package org.shem.delivery;

import java.util.List;
import org.shem.common.OpaqueId;

/**
 * One SMTP transaction (or local submission/DSN). {@code transactionId} plus recipient index forms
 * each recipient's internal delivery id for idempotent receipt replay.
 */
public record DeliveryRequest(
    OpaqueId transactionId,
    List<RecipientDelivery> recipients,
    MessageSource message,
    long internalDateMillis,
    String envelopeSender) {
  public DeliveryRequest {
    recipients = List.copyOf(recipients);
  }
}
