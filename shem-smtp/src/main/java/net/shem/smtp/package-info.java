/**
 * Inbound SMTP (MX, port 25) built from Apache James protocol handlers (ADR 0009). The role never
 * unlocks a mailbox: accepted mail goes straight to {@link net.shem.delivery.DeliveryService}.
 */
@NullMarked
package net.shem.smtp;

import org.jspecify.annotations.NullMarked;
