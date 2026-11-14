/**
 * Locked-mailbox delivery. Uses only recipient public keys: writes an immutable encrypted blob and
 * an encrypted receipt per recipient, and acknowledges only after both are durable.
 */
@NullMarked
package net.shem.delivery;

import org.jspecify.annotations.NullMarked;
