/**
 * Identity and administration: the public routing directory that must work while mailboxes are
 * locked. It holds addresses, opaque mailbox ids, lifecycle state, quotas, and public keys, and
 * deliberately nothing about folders, messages, flags, or counters.
 */
@NullMarked
package org.shem.identity;

import org.jspecify.annotations.NullMarked;
