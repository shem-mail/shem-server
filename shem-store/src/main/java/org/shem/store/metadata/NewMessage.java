package org.shem.store.metadata;

import org.shem.common.ImmutableBytes;
import org.shem.common.OpaqueId;

/** A message to add to a folder; the store assigns UID and modseq. */
public record NewMessage(
    OpaqueId blobId,
    ImmutableBytes wrappedContentKey,
    long size,
    long internalDateMillis,
    Flags flags,
    ImmutableBytes summary) {}
