package org.shem.smtp;

import java.util.List;
import org.apache.james.core.MailAddress;
import org.apache.james.core.MaybeSender;
import org.apache.james.protocols.api.ProtocolSession;
import org.apache.james.protocols.smtp.SMTPRetCode;
import org.apache.james.protocols.smtp.SMTPSession;
import org.apache.james.protocols.smtp.hook.HookResult;
import org.apache.james.protocols.smtp.hook.HookReturnCode;
import org.apache.james.protocols.smtp.hook.RcptHook;
import org.shem.identity.EmailAddress;
import org.shem.identity.IdentityException;
import org.shem.identity.IdentityService;
import org.shem.identity.RecipientRoute;

/**
 * Accepts a recipient only if it resolves to at least one accepting local mailbox. Never relays: a
 * recipient in a non-local domain is refused regardless of client address. Unknown, disabled, and
 * deleted recipients get one identical response (anti-enumeration), and a connection that
 * accumulates too many of them is closed. This hook never returns DECLINED, so James's default
 * acceptance cannot apply.
 */
final class RecipientPolicy implements RcptHook {
  private static final HookResult RELAY_DENIED =
      deny(HookReturnCode.deny(), SMTPRetCode.MAILBOX_PERM_UNAVAILABLE, "5.7.1 Relaying denied");
  private static final HookResult UNKNOWN =
      deny(HookReturnCode.deny(), SMTPRetCode.MAILBOX_PERM_UNAVAILABLE, "5.1.1 Recipient rejected");
  private static final HookResult BAD_ADDRESS =
      deny(
          HookReturnCode.deny(),
          SMTPRetCode.SYNTAX_ERROR_MAILBOX,
          "5.1.3 Bad recipient address syntax");
  private static final HookResult TOO_MANY =
      deny(
          HookReturnCode.denySoft(), SMTPRetCode.SYSTEM_STORAGE_ERROR, "4.5.3 Too many recipients");
  private static final HookResult UNAVAILABLE =
      deny(HookReturnCode.denySoft(), SMTPRetCode.LOCAL_ERROR, "4.3.0 Try again later");
  private static final HookResult GOODBYE =
      deny(
          HookReturnCode.disconnected(HookReturnCode.Action.DENYSOFT),
          SMTPRetCode.SERVICE_NOT_AVAILABLE,
          "4.7.0 Too many rejected recipients, closing connection");
  private static final HookResult ACCEPTED =
      HookResult.builder()
          .hookReturnCode(HookReturnCode.ok())
          .smtpReturnCode(SMTPRetCode.MAIL_OK)
          .smtpDescription("2.1.5 Recipient OK")
          .build();

  private final IdentityService identity;
  private final int maxRecipients;
  private final int maxUnknownRecipients;
  private final InboundMetrics metrics;

  RecipientPolicy(
      IdentityService identity,
      int maxRecipients,
      int maxUnknownRecipients,
      InboundMetrics metrics) {
    this.identity = identity;
    this.maxRecipients = maxRecipients;
    this.maxUnknownRecipients = maxUnknownRecipients;
    this.metrics = metrics;
  }

  private static HookResult deny(HookReturnCode code, String smtpCode, String description) {
    return HookResult.builder()
        .hookReturnCode(code)
        .smtpReturnCode(smtpCode)
        .smtpDescription(description)
        .build();
  }

  @Override
  public HookResult doRcpt(SMTPSession session, MaybeSender sender, MailAddress rcpt) {
    EmailAddress address;
    try {
      address = EmailAddress.parse(rcpt.asString());
    } catch (IllegalArgumentException e) {
      return BAD_ADDRESS;
    }
    if (!identity.isLocalDomain(address.domain())) {
      metrics.relayDenied.increment();
      return RELAY_DENIED;
    }
    Transactions.Recipients recipients = Transactions.recipients(session);
    if (recipients.count() >= maxRecipients) {
      metrics.tooManyRecipients.increment();
      return TOO_MANY;
    }
    List<RecipientRoute> routes;
    try {
      routes = identity.resolveRecipient(address);
    } catch (IdentityException e) {
      metrics.temporaryFailure.increment();
      return UNAVAILABLE;
    }
    if (routes.isEmpty()) {
      metrics.unknownRecipient.increment();
      int unknown =
          session
                  .getAttachment(Transactions.UNKNOWN_RECIPIENTS, ProtocolSession.State.Connection)
                  .orElse(0)
              + 1;
      session.setAttachment(
          Transactions.UNKNOWN_RECIPIENTS, unknown, ProtocolSession.State.Connection);
      return unknown > maxUnknownRecipients ? GOODBYE : UNKNOWN;
    }
    recipients.add(address.localPart() + "@" + address.domain(), routes);
    return ACCEPTED;
  }
}
