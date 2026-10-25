package org.shem.imap;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.concurrent.atomic.AtomicLong;
import org.apache.james.core.Username;
import org.apache.james.imap.api.display.HumanReadableText;
import org.apache.james.imap.api.process.ImapSession;
import org.apache.james.mailbox.MailboxSession;
import org.shem.mailbox.AuthenticationException;
import org.shem.mailbox.Capability;
import org.shem.mailbox.MailboxLease;
import org.shem.mailbox.SessionService;
import org.shem.store.StorageException;

/**
 * Shared credential handling for LOGIN and AUTHENTICATE PLAIN: refuses plaintext channels, passes
 * the client address to Shem's shared limiter, and binds the resulting unlock lease to the IMAP
 * session. Credentials are never logged or stored in session attributes.
 */
final class ImapAuthentication {
  private static final String FAILURES = "shem.auth.failures";
  static final int MAX_FAILURES_PER_CONNECTION = 3;

  private final SessionService sessions;
  private final EventPublisher events;
  private final AtomicLong sessionIds = new AtomicLong(1);

  ImapAuthentication(SessionService sessions, EventPublisher events) {
    this.sessions = sessions;
    this.events = events;
  }

  /** Outcome mapped to IMAP responses by the calling processor. */
  enum Result {
    OK,
    INVALID,
    THROTTLED,
    TOO_MANY_FAILURES,
    UNAVAILABLE
  }

  Result authenticate(ImapSession session, String username, String password) {
    InetSocketAddress remote = session.getRemoteAddress();
    InetAddress source = remote == null ? InetAddress.getLoopbackAddress() : remote.getAddress();
    MailboxLease lease;
    try {
      lease = sessions.authenticate(username, password, source, Capability.MAIL_ACCESS);
    } catch (AuthenticationException e) {
      return switch (e.reason()) {
        case THROTTLED -> Result.THROTTLED;
        case UNAVAILABLE -> Result.UNAVAILABLE;
        case INVALID, NOT_PERMITTED -> countFailure(session);
      };
    }
    try {
      Username user = Username.of(lease.principal().address().toString());
      events.attach(lease, user);
      MailboxSession mailboxSession = Sessions.create(user, lease, sessionIds.incrementAndGet());
      session.authenticated();
      session.setMailboxSession(mailboxSession);
      session.stopDetectingCommandInjection();
      return Result.OK;
    } catch (StorageException | RuntimeException e) {
      lease.close();
      return Result.UNAVAILABLE;
    }
  }

  private static Result countFailure(ImapSession session) {
    Object current = session.getAttribute(FAILURES);
    int failures = (current instanceof Integer i ? i : 0) + 1;
    session.setAttribute(FAILURES, failures);
    return failures >= MAX_FAILURES_PER_CONNECTION ? Result.TOO_MANY_FAILURES : Result.INVALID;
  }

  static HumanReadableText text(Result result) {
    return switch (result) {
      case OK -> HumanReadableText.COMPLETED;
      case INVALID, TOO_MANY_FAILURES -> HumanReadableText.INVALID_LOGIN;
      case THROTTLED, UNAVAILABLE -> HumanReadableText.GENERIC_FAILURE_DURING_PROCESSING;
    };
  }
}
