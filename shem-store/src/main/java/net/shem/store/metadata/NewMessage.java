package net.shem.store.metadata;

import net.shem.common.ImmutableBytes;
import net.shem.common.OpaqueId;

/** A message to add to a folder; the store assigns UID and modseq. */
public record NewMessage(
    OpaqueId blobId,
    ImmutableBytes wrappedContentKey,
    long size,
    long internalDateMillis,
    Flags flags,
    ImmutableBytes summary) {}
