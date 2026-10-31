package org.shem.smtp;

import java.util.List;
import org.apache.james.core.MailAddress;
import org.apache.james.core.MaybeSender;
import org.apache.james.protocols.api.ProtocolSession;
import org.apache.james.protocols.api.handler.DisconnectHandler;
import org.apache.james.protocols.smtp.SMTPRetCode;
import org.apache.james.protocols.smtp.SMTPSession;
import org.apache.james.protocols.smtp.hook.HookResult;
import org.apache.james.protocols.smtp.hook.HookReturnCode;
import org.apache.james.protocols.smtp.hook.MailHook;
import org.apache.james.protocols.smtp.hook.RcptHook;
import org.shem.identity.EmailAddress;
import org.shem.identity.IdentityException;
import org.shem.identity.IdentityService;
import org.shem.identity.RecipientRoute;
import org.shem.mailbox.MailboxLease;

/**
 * Submission envelope rules. MAIL requires a valid authenticated lease (and therefore TLS) and an
 * envelope sender the account may use; RCPT accepts local recipients only (remote delivery is plan
 * step 13) within the per-message and per-hour limits. The lease is closed on disconnect.
 */
final class SubmissionHooks implements MailHook, RcptHook, DisconnectHandler<SMTPSession> {
  private static final HookResult AUTH_REQUIRED =
      result(HookReturnCode.deny(), "530", "5.7.0 Authentication required");
  private static final HookResult REVOKED;
  private static final HookResult NULL_SENDER =
      result(
          HookReturnCode.deny(),
          SMTPRetCode.SYNTAX_ERROR_MAILBOX,
          "5.7.1 A sender address is required");
  private static final HookResult SENDER_DENIED =
      result(
          HookReturnCode.deny(),
          SMTPRetCode.SYNTAX_ERROR_MAILBOX,
          "5.7.1 Sender address not authorized for this account");
  private static final HookResult SENDER_OK =
      result(HookReturnCode.ok(), SMTPRetCode.MAIL_OK, "2.1.0 Sender OK");
  private static final HookResult REMOTE =
      result(
          HookReturnCode.deny(),
          SMTPRetCode.MAILBOX_PERM_UNAVAILABLE,
          "5.7.0 Remote delivery is not available on this server");
  private static final HookResult UNKNOWN =
      result(
          HookReturnCode.deny(), SMTPRetCode.MAILBOX_PERM_UNAVAILABLE, "5.1.1 Recipient rejected");
  private static final HookResult BAD_ADDRESS =
      result(
          HookReturnCode.deny(),
          SMTPRetCode.SYNTAX_ERROR_MAILBOX,
          "5.1.3 Bad recipient address syntax");
  private static final HookResult TOO_MANY =
      result(
          HookReturnCode.denySoft(), SMTPRetCode.SYSTEM_STORAGE_ERROR, "4.5.3 Too many recipients");
  private static final HookResult RATE =
      result(
          HookReturnCode.denySoft(),
          SMTPRetCode.LOCAL_ERROR,
          "4.7.0 Sending rate exceeded, try again later");
  private static final HookResult UNAVAILABLE =
      result(HookReturnCode.denySoft(), SMTPRetCode.LOCAL_ERROR, "4.3.0 Try again later");
  private static final HookResult ACCEPTED =
      result(HookReturnCode.ok(), SMTPRetCode.MAIL_OK, "2.1.5 Recipient OK");

  static {
    REVOKED =
        result(
            HookReturnCode.disconnected(HookReturnCode.Action.DENY),
            SMTPRetCode.SERVICE_NOT_AVAILABLE,
            "4.7.0 Session no longer authorized");
  }

  private final IdentityService identity;
  private final SendRate rate;
  private final int maxRecipients;
  private final boolean relay;

  /** {@code relay}: remote recipients go to the outbound queue; otherwise they are refused. */
  SubmissionHooks(IdentityService identity, SendRate rate, int maxRecipients, boolean relay) {
    this.relay = relay;
    this.identity = identity;
    this.rate = rate;
    this.maxRecipients = maxRecipients;
  }

  private static HookResult result(HookReturnCode code, String smtpCode, String description) {
    return HookResult.builder()
        .hookReturnCode(code)
        .smtpReturnCode(smtpCode)
        .smtpDescription(description)
        .build();
  }

  /** Authorization check shared by every submission stage. */
  static HookResult authorization(SMTPSession session) {
    if (session.getAttachment(SubmissionAuth.LEASE, ProtocolSession.State.Connection).isEmpty()) {
      return AUTH_REQUIRED;
    }
    return SubmissionAuth.lease(session) == null ? REVOKED : HookResult.DECLINED;
  }

  @Override
  public HookResult doMail(SMTPSession session, MaybeSender sender) {
    HookResult authorization = authorization(session);
    MailboxLease lease = SubmissionAuth.lease(session);
    if (lease == null) {
      return authorization;
    }
    if (sender.isNullSender()) {
      return NULL_SENDER;
    }
    EmailAddress address;
    try {
      address = EmailAddress.parse(sender.get().asString());
    } catch (IllegalArgumentException e) {
      return SENDER_DENIED;
    }
    return identity.mayUseSenderIdentity(lease.mailboxId(), address) ? SENDER_OK : SENDER_DENIED;
  }

  @Override
  public HookResult doRcpt(SMTPSession session, MaybeSender sender, MailAddress rcpt) {
    MailboxLease lease = SubmissionAuth.lease(session);
    if (lease == null) {
      return authorization(session);
    }
    EmailAddress address;
    try {
      address = EmailAddress.parse(rcpt.asString());
    } catch (IllegalArgumentException e) {
      return BAD_ADDRESS;
    }
    Transactions.Recipients recipients = Transactions.recipients(session);
    if (!identity.isLocalDomain(address.domain())) {
      if (!relay) {
        return REMOTE;
      }
      if (recipients.count() >= maxRecipients) {
        return TOO_MANY;
      }
      if (!rate.take(lease.mailboxId())) {
        return RATE;
      }
      recipients.addRemote(address.toString());
      return ACCEPTED;
    }
    if (recipients.count() >= maxRecipients) {
      return TOO_MANY;
    }
    List<RecipientRoute> routes;
    try {
      routes = identity.resolveRecipient(address);
    } catch (IdentityException e) {
      return UNAVAILABLE;
    }
    if (routes.isEmpty()) {
      return UNKNOWN;
    }
    if (!rate.take(lease.mailboxId())) {
      return RATE;
    }
    recipients.add(address.toString(), routes);
    return ACCEPTED;
  }

  @Override
  public void onDisconnect(SMTPSession session) {
    session
        .getAttachment(SubmissionAuth.LEASE, ProtocolSession.State.Connection)
        .ifPresent(MailboxLease::close);
  }
}
