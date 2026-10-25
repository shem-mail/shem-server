package org.shem.smtp;

import java.io.IOException;
import java.io.InputStream;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.apache.james.core.MailAddress;
import org.apache.james.protocols.smtp.MailEnvelope;
import org.apache.james.protocols.smtp.SMTPRetCode;
import org.apache.james.protocols.smtp.SMTPSession;
import org.apache.james.protocols.smtp.hook.HookResult;
import org.apache.james.protocols.smtp.hook.HookReturnCode;
import org.apache.james.protocols.smtp.hook.MessageHook;
import org.jspecify.annotations.Nullable;
import org.shem.common.IdGenerator;
import org.shem.delivery.DeliveryRequest;
import org.shem.delivery.DeliveryService;
import org.shem.delivery.MessageSource;
import org.shem.delivery.RecipientDelivery;
import org.shem.delivery.RecipientOutcome;
import org.shem.identity.EmailAddress;
import org.shem.identity.IdentityService;
import org.shem.mailbox.MailboxLease;
import org.shem.outbound.DkimSigning;
import org.shem.outbound.OutboundQueue;
import org.shem.policy.HeaderIdentities;
import org.shem.store.DeliveryTarget;
import org.shem.store.SpecialUse;

/**
 * Delivers a submitted message after checking that every From and Sender address belongs to the
 * authenticated account: DKIM-signed when the From domain has a key, queued durably for remote
 * recipients, and delivered encrypted to local ones. An all-local message never touches the
 * plaintext queue. Sent copies are left to the client (IMAP APPEND), so nothing is filed in the
 * sender's Sent folder (ADR 0011).
 */
final class SubmissionDelivery implements MessageHook {
  private static final System.Logger LOG = System.getLogger(SubmissionDelivery.class.getName());

  private final DeliveryService delivery;
  private final IdentityService identity;
  private final IdGenerator ids;
  private final Clock clock;
  private final SubmissionRole.@Nullable Relay relay;

  SubmissionDelivery(
      DeliveryService delivery,
      IdentityService identity,
      IdGenerator ids,
      Clock clock,
      SubmissionRole.@Nullable Relay relay) {
    this.relay = relay;
    this.delivery = delivery;
    this.identity = identity;
    this.ids = ids;
    this.clock = clock;
  }

  private static HookResult result(HookReturnCode code, String smtpCode, String description) {
    return HookResult.builder()
        .hookReturnCode(code)
        .smtpReturnCode(smtpCode)
        .smtpDescription(description)
        .build();
  }

  @Override
  public HookResult onMessage(SMTPSession session, MailEnvelope mail) {
    if (!(mail instanceof SpoolingEnvelope envelope)) {
      throw new IllegalStateException("unexpected envelope type");
    }
    try {
      return deliver(session, envelope);
    } finally {
      try {
        Transactions.discard(session, envelope);
      } catch (IOException e) {
        LOG.log(
            System.Logger.Level.WARNING, "spool cleanup failed: {0}", e.getClass().getSimpleName());
      }
    }
  }

  private HookResult deliver(SMTPSession session, SpoolingEnvelope envelope) {
    MailboxLease lease = SubmissionAuth.lease(session);
    if (lease == null) {
      return SubmissionHooks.authorization(session);
    }
    if (!envelope.sealed()) {
      return result(HookReturnCode.denySoft(), SMTPRetCode.LOCAL_ERROR, "4.3.0 Try again later");
    }
    Optional<List<String>> authors;
    try (InputStream in = envelope.open()) {
      authors = HeaderIdentities.authors(in);
    } catch (IOException e) {
      return result(HookReturnCode.denySoft(), SMTPRetCode.LOCAL_ERROR, "4.3.0 Try again later");
    }
    if (authors.isEmpty()) {
      return result(
          HookReturnCode.deny(),
          SMTPRetCode.TRANSACTION_FAILED,
          "5.6.0 Message must have exactly one valid From header");
    }
    for (String author : authors.get()) {
      boolean allowed;
      try {
        allowed = identity.mayUseSenderIdentity(lease.mailboxId(), EmailAddress.parse(author));
      } catch (IllegalArgumentException e) {
        allowed = false;
      }
      if (!allowed) {
        return result(
            HookReturnCode.deny(),
            SMTPRetCode.TRANSACTION_FAILED,
            "5.7.1 From or Sender address not authorized for this account");
      }
    }
    MessageSource signed = envelope;
    String fromDomain = authors.get().getFirst();
    fromDomain = fromDomain.substring(fromDomain.lastIndexOf('@') + 1);
    SubmissionRole.Relay outbound = relay;
    if (outbound != null) {
      try {
        signed = outbound.dkim().sign(fromDomain, envelope);
      } catch (IOException | DkimSigning.SigningException e) {
        LOG.log(
            System.Logger.Level.ERROR, "DKIM signing failed: {0}", e.getClass().getSimpleName());
        return result(HookReturnCode.denySoft(), SMTPRetCode.LOCAL_ERROR, "4.3.0 Try again later");
      }
    }
    List<String> remote = Transactions.recipients(session).remote();
    String envelopeSender =
        envelope.getMaybeSender().asOptional().map(MailAddress::asString).orElse("");
    if (!remote.isEmpty()) {
      if (outbound == null) {
        return result(
            HookReturnCode.deny(),
            SMTPRetCode.MAILBOX_PERM_UNAVAILABLE,
            "5.7.0 Remote delivery is not available on this server");
      }
      // Queue first: a full queue then refuses the transaction before any local copy commits.
      try {
        outbound.queue().enqueue(envelopeSender, remote, signed);
      } catch (OutboundQueue.QueueFullException e) {
        return result(
            HookReturnCode.denySoft(),
            SMTPRetCode.SYSTEM_STORAGE_ERROR,
            "4.3.1 Outbound queue full, try again later");
      } catch (IOException e) {
        LOG.log(System.Logger.Level.ERROR, "queue write failed: {0}", e.getClass().getSimpleName());
        return result(HookReturnCode.denySoft(), SMTPRetCode.LOCAL_ERROR, "4.3.0 Try again later");
      }
    }
    List<RecipientDelivery> recipients = new ArrayList<>();
    for (Transactions.Recipients.Accepted a : Transactions.recipients(session).mailboxes()) {
      recipients.add(
          new RecipientDelivery(
              a.route(),
              a.address(),
              new DeliveryTarget.Role(SpecialUse.INBOX),
              0,
              List.of(),
              List.of("submission")));
    }
    if (recipients.isEmpty()) {
      return remote.isEmpty()
          ? result(
              HookReturnCode.deny(), SMTPRetCode.TRANSACTION_FAILED, "5.5.1 No valid recipients")
          : result(HookReturnCode.ok(), SMTPRetCode.MAIL_OK, "2.6.0 Message queued for delivery");
    }
    List<RecipientOutcome> outcomes;
    try {
      outcomes =
          delivery.deliver(
              new DeliveryRequest(ids.next(), recipients, signed, clock.millis(), envelopeSender));
    } catch (RuntimeException e) {
      LOG.log(System.Logger.Level.ERROR, "delivery failed: {0}", e.getClass().getSimpleName());
      return result(HookReturnCode.denySoft(), SMTPRetCode.LOCAL_ERROR, "4.3.0 Try again later");
    }
    for (RecipientOutcome outcome : outcomes) {
      if (outcome instanceof RecipientOutcome.Failed failed) {
        return failed.permanent()
            ? result(HookReturnCode.deny(), SMTPRetCode.QUOTA_EXCEEDED, "5.3.4 Message too large")
            : failed.reason() == RecipientOutcome.Reason.QUOTA_EXCEEDED
                ? result(
                    HookReturnCode.denySoft(),
                    SMTPRetCode.SYSTEM_STORAGE_ERROR,
                    "4.2.2 Recipient mailbox full")
                : result(
                    HookReturnCode.denySoft(), SMTPRetCode.LOCAL_ERROR, "4.3.0 Try again later");
      }
    }
    return result(HookReturnCode.ok(), SMTPRetCode.MAIL_OK, "2.6.0 Message accepted for delivery");
  }
}
