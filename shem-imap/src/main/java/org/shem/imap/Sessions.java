package org.shem.imap;

import java.util.List;
import java.util.Locale;
import java.util.Optional;
import org.apache.james.core.Username;
import org.apache.james.mailbox.MailboxSession;
import org.apache.james.mailbox.exception.MailboxException;
import org.jspecify.annotations.Nullable;
import org.shem.mailbox.MailboxLease;
import org.shem.mailbox.RevokedLeaseException;

/** Binds a Shem lease to a James mailbox session via the session's attribute map. */
final class Sessions {
  static final char DELIMITER = '.';
  private static final String LEASE = "shem.lease";

  private Sessions() {}

  static MailboxSession create(Username user, MailboxLease lease, long id) {
    MailboxSession session =
        new MailboxSession(
            MailboxSession.SessionId.of(id),
            user,
            Optional.of(user),
            List.of(Locale.ROOT),
            DELIMITER,
            MailboxSession.SessionType.User);
    session.getAttributes().put(LEASE, lease);
    return session;
  }

  static @Nullable MailboxLease leaseOrNull(@Nullable MailboxSession session) {
    if (session == null) {
      return null;
    }
    Object lease = session.getAttributes().get(LEASE);
    return lease instanceof MailboxLease l ? l : null;
  }

  /** The session's lease; fails like a closed session once revoked. */
  static MailboxLease lease(MailboxSession session) throws MailboxException {
    MailboxLease lease = leaseOrNull(session);
    if (lease == null || !lease.isValid()) {
      throw new MailboxException("session no longer authorized", new RevokedLeaseException());
    }
    return lease;
  }
}
