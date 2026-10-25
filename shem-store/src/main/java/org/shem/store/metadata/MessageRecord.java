package org.shem.store.metadata;

import org.shem.common.ImmutableBytes;
import org.shem.common.OpaqueId;

/**
 * Per-folder message entry.
 *
 * @param blobId immutable encrypted blob; also the stable message id for search
 * @param wrappedContentKey content key wrapped under the mailbox data key
 * @param size plaintext RFC 5322 size in bytes
 * @param internalDateMillis IMAP INTERNALDATE
 * @param modSeq modification sequence of the last change to this entry
 * @param summary precomputed encrypted-at-rest envelope/bodystructure (opaque to the store)
 */
public record MessageRecord(
    OpaqueId blobId,
    ImmutableBytes wrappedContentKey,
    long size,
    long internalDateMillis,
    long modSeq,
    Flags flags,
    ImmutableBytes summary) {
  public static final int MAX_SUMMARY_BYTES = 256 * 1024;

  public MessageRecord {
    if (size < 0 || modSeq < 1 || summary.length() > MAX_SUMMARY_BYTES) {
      throw new IllegalArgumentException("invalid message record");
    }
  }

  MessageRecord withFlags(Flags newFlags, long newModSeq) {
    return new MessageRecord(
        blobId, wrappedContentKey, size, internalDateMillis, newModSeq, newFlags, summary);
  }

  MessageRecord withModSeq(long newModSeq) {
    return new MessageRecord(
        blobId, wrappedContentKey, size, internalDateMillis, newModSeq, flags, summary);
  }
}
