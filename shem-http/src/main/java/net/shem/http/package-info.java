/**
 * HTTPS API (ADR 0013). Sessions are opaque random tokens that map, in memory only, to a {@link
 * net.shem.mailbox.MailboxLease}; key material never leaves the server and never reaches a client.
 */
@NullMarked
package net.shem.http;

import org.jspecify.annotations.NullMarked;
