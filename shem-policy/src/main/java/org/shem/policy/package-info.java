/**
 * Inbound mail policy (ADR 0010). Everything here is bounded and in memory: no address tuples,
 * results, or content models are persisted. Per-message results travel only inside the encrypted
 * message and receipt.
 */
@NullMarked
package org.shem.policy;

import org.jspecify.annotations.NullMarked;
