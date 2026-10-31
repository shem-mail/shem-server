package org.shem.delivery;

import org.shem.common.OpaqueId;

/** Result for one recipient. */
public sealed interface RecipientOutcome {
  /** Blob and receipt are durable; it is safe to acknowledge this recipient. */
  record Delivered(OpaqueId mailboxId, OpaqueId deliveryId, OpaqueId receiptId)
      implements RecipientOutcome {}

  /** Not delivered. {@code permanent} distinguishes 5xx-style from 4xx-style failures. */
  record Failed(OpaqueId mailboxId, Reason reason) implements RecipientOutcome {
    public boolean permanent() {
      return reason == Reason.TOO_LARGE;
    }
  }

  /** Failure reason codes (safe to log). */
  enum Reason {
    QUOTA_EXCEEDED,
    TOO_LARGE,
    STORAGE_UNAVAILABLE
  }
}
