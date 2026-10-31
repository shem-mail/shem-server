/**
 * The authenticated role's mailbox services: credential unlock with shared abuse limits, unlock
 * leases, the single mailbox coordinator per unlocked mailbox, receipt import, and key lifecycle.
 * Protocol adapters receive leases and principals, never raw keys.
 */
@NullMarked
package org.shem.mailbox;

import org.jspecify.annotations.NullMarked;
