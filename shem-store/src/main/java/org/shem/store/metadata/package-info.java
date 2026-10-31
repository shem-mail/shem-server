/**
 * Encrypted per-mailbox metadata: folders, membership, flags, content-key wraps, and replay
 * checkpoints, stored as an authenticated append-only journal plus sorted encrypted snapshots. See
 * {@code docs/adr/0004-metadata-store.md}.
 */
@NullMarked
package org.shem.store.metadata;

import org.jspecify.annotations.NullMarked;
