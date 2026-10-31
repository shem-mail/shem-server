/**
 * Outbound delivery (ADR 0012). The queue under {@code queue/} holds readable message content and
 * envelope data: the whitepaper's single deliberate exception to encryption at rest. It never holds
 * passwords, mailbox keys, or unlock tokens.
 */
@NullMarked
package org.shem.outbound;

import org.jspecify.annotations.NullMarked;
