package org.shem.delivery;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import org.shem.common.OpaqueId;
import org.shem.crypto.CryptoProfile;
import org.shem.identity.QuotaLedger;
import org.shem.store.BlobStore;
import org.shem.store.Receipt;
import org.shem.store.ReceiptStore;
import org.shem.store.StorageException;

/**
 * Durable delivery using only public keys. For each recipient: reserve quota, write and sync an
 * immutable blob under a fresh content key, write and sync a receipt sealed to the recipient's
 * public key, then report success. Ciphertext is randomized per recipient (no cross-user dedup).
 */
public final class DeliveryService {
  /** Conservative fixed allowance for the receipt file and headers. */
  private static final long RECEIPT_ALLOWANCE = 8 * 1024;

  private final BlobStore blobs;
  private final ReceiptStore receipts;
  private final QuotaLedger quota;
  private final DeliveryListener listener;
  private final long maxMessageBytes;

  public DeliveryService(
      BlobStore blobs,
      ReceiptStore receipts,
      QuotaLedger quota,
      DeliveryListener listener,
      long maxMessageBytes) {
    this.blobs = blobs;
    this.receipts = receipts;
    this.quota = quota;
    this.listener = listener;
    this.maxMessageBytes = maxMessageBytes;
  }

  public long maxMessageBytes() {
    return maxMessageBytes;
  }

  public List<RecipientOutcome> deliver(DeliveryRequest request) {
    List<RecipientOutcome> outcomes = new ArrayList<>();
    for (int i = 0; i < request.recipients().size(); i++) {
      outcomes.add(deliverOne(request, i));
    }
    return outcomes;
  }

  private RecipientOutcome deliverOne(DeliveryRequest request, int index) {
    RecipientDelivery recipient = request.recipients().get(index);
    OpaqueId mailboxId = recipient.route().mailboxId();
    if (request.message().size() > maxMessageBytes) {
      return new RecipientOutcome.Failed(mailboxId, RecipientOutcome.Reason.TOO_LARGE);
    }
    OpaqueId deliveryId = deliveryId(request.transactionId(), index);
    long estimate = estimateCiphertext(request.message().size()) + RECEIPT_ALLOWANCE;
    try (QuotaLedger.Reservation reservation =
        quota.reserve(mailboxId, estimate, recipient.route().quotaBytes())) {
      BlobStore.WrittenBlob blob;
      try (InputStream in = request.message().open()) {
        blob = blobs.write(mailboxId, in, maxMessageBytes);
      }
      // If the receipt write fails the blob is an unreferenced orphan; GC reclaims it.
      ReceiptStore.PendingReceipt pending;
      try (Receipt receipt =
          new Receipt(
              deliveryId,
              blob.blobId(),
              blob.contentKey(),
              blob.plaintextBytes(),
              request.internalDateMillis(),
              recipient.systemFlags(),
              recipient.keywords(),
              recipient.target(),
              request.envelopeSender(),
              recipient.recipientAddress(),
              recipient.policyTags())) {
        pending = receipts.write(mailboxId, recipient.route().publicKey(), receipt);
      }
      reservation.commit(blob.ciphertextBytes() + RECEIPT_ALLOWANCE);
      listener.delivered(mailboxId);
      return new RecipientOutcome.Delivered(mailboxId, deliveryId, pending.receiptId());
    } catch (QuotaLedger.QuotaExceeded e) {
      return new RecipientOutcome.Failed(mailboxId, RecipientOutcome.Reason.QUOTA_EXCEEDED);
    } catch (StorageException e) {
      return new RecipientOutcome.Failed(
          mailboxId,
          e.kind() == StorageException.Kind.LIMIT_EXCEEDED
              ? RecipientOutcome.Reason.TOO_LARGE
              : RecipientOutcome.Reason.STORAGE_UNAVAILABLE);
    } catch (IOException e) {
      return new RecipientOutcome.Failed(mailboxId, RecipientOutcome.Reason.STORAGE_UNAVAILABLE);
    }
  }

  /** Deterministic per-recipient id derived from the transaction id and recipient index. */
  static OpaqueId deliveryId(OpaqueId transactionId, int index) {
    byte[] bytes = transactionId.toBytes();
    bytes[OpaqueId.BYTES - 2] ^= (byte) (index >>> 8);
    bytes[OpaqueId.BYTES - 1] ^= (byte) index;
    return OpaqueId.fromBytes(bytes);
  }

  static long estimateCiphertext(long plaintext) {
    long segments = plaintext / (CryptoProfile.BLOB_SEGMENT_BYTES - 16) + 1;
    return plaintext + segments * 16 + 64;
  }
}
