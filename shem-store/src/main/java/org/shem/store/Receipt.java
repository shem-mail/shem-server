package org.shem.store;

import java.util.List;
import org.shem.common.OpaqueId;
import org.shem.crypto.SymmetricKey;

/**
 * Decrypted delivery receipt: everything needed to import a delivered blob into mailbox metadata.
 * Persisted only encrypted to the recipient's public key. Owns {@code contentKey}.
 *
 * @param deliveryId internal transaction id used for idempotent replay
 * @param envelopeSender SMTP reverse path (private; may be empty for bounces)
 * @param recipient the address the message was delivered to (private)
 * @param policyTags compact policy outcomes such as {@code spam}; never message content
 */
public record Receipt(
    OpaqueId deliveryId,
    OpaqueId blobId,
    SymmetricKey contentKey,
    long plaintextBytes,
    long internalDateMillis,
    int systemFlags,
    List<String> keywords,
    DeliveryTarget target,
    String envelopeSender,
    String recipient,
    List<String> policyTags)
    implements AutoCloseable {
  public Receipt {
    keywords = List.copyOf(keywords);
    policyTags = List.copyOf(policyTags);
  }

  @Override
  public void close() {
    contentKey.close();
  }
}
