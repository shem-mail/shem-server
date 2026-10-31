/**
 * HTTPS API (ADR 0013). Sessions are opaque random tokens that map, in memory only, to a {@link
 * org.shem.mailbox.MailboxLease}; key material never leaves the server and never reaches a client.
 */
@NullMarked
package org.shem.http;

import org.jspecify.annotations.NullMarked;
