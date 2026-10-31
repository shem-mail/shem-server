package org.shem.smtp;

import java.io.IOException;
import java.io.InputStream;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import org.apache.james.core.MailAddress;
import org.apache.james.protocols.api.ProtocolSession;
import org.apache.james.protocols.smtp.MailEnvelope;
import org.apache.james.protocols.smtp.SMTPRetCode;
import org.apache.james.protocols.smtp.SMTPSession;
import org.apache.james.protocols.smtp.hook.HookResult;
import org.apache.james.protocols.smtp.hook.HookReturnCode;
import org.apache.james.protocols.smtp.hook.MessageHook;
import org.shem.common.IdGenerator;
import org.shem.delivery.DeliveryRequest;
import org.shem.delivery.DeliveryService;
import org.shem.delivery.MessageSource;
import org.shem.delivery.RecipientDelivery;
import org.shem.delivery.RecipientOutcome;
import org.shem.policy.HeaderRewriter;
import org.shem.policy.InboundPolicy;
import org.shem.store.DeliveryTarget;
import org.shem.store.SpecialUse;

/**
 * Hands the completed message to {@link DeliveryService} and answers DATA. {@code 250} is sent only
 * when every accepted mailbox has a durable blob and receipt. If any mailbox fails, the whole
 * transaction gets a failure reply: a temporary one if any failure is temporary, so the client
 * retries; mailboxes that already committed may then receive a duplicate (ADR 0009). Runs on
 * James's bounded handler executor, never on a Netty event loop.
 */
final class DeliveryHook implements MessageHook {
  private static final System.Logger LOG = System.getLogger(DeliveryHook.class.getName());
  private static final HookResult ACCEPTED =
      result(HookReturnCode.ok(), SMTPRetCode.MAIL_OK, "2.6.0 Message accepted for delivery");
  private static final HookResult TEMPORARY =
      result(HookReturnCode.denySoft(), SMTPRetCode.LOCAL_ERROR, "4.3.0 Try again later");
  private static final HookResult MAILBOX_FULL =
      result(
          HookReturnCode.denySoft(),
          SMTPRetCode.SYSTEM_STORAGE_ERROR,
          "4.2.2 Mailbox full, try again later");
  private static final HookResult TOO_BIG =
      result(
          HookReturnCode.deny(),
          SMTPRetCode.QUOTA_EXCEEDED,
          "5.3.4 Message size exceeds fixed maximum message size");
  private static final HookResult NO_RECIPIENTS =
      result(HookReturnCode.deny(), SMTPRetCode.TRANSACTION_FAILED, "5.5.1 No valid recipients");

  private final DeliveryService delivery;
  private final IdGenerator ids;
  private final Clock clock;
  private final InboundMetrics metrics;
  private final InboundPolicy policy;

  DeliveryHook(
      DeliveryService delivery,
      InboundPolicy policy,
      IdGenerator ids,
      Clock clock,
      InboundMetrics metrics) {
    this.policy = policy;
    this.delivery = delivery;
    this.ids = ids;
    this.clock = clock;
    this.metrics = metrics;
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
        // Key already wiped; the leftover ciphertext is removed by the start-up sweep. The reply
        // was decided by the durable delivery result above.
        LOG.log(
            System.Logger.Level.WARNING, "spool cleanup failed: {0}", e.getClass().getSimpleName());
      }
    }
  }

  private HookResult deliver(SMTPSession session, SpoolingEnvelope envelope) {
    if (!envelope.sealed()) {
      metrics.temporaryFailure.increment();
      return TEMPORARY;
    }
    List<Transactions.Recipients.Accepted> accepted = Transactions.recipients(session).mailboxes();
    if (accepted.isEmpty()) {
      return NO_RECIPIENTS;
    }
    if (envelope.spooled()) {
      metrics.spooled.increment();
    }
    String sender = envelope.getMaybeSender().asOptional().map(MailAddress::asString).orElse("");
    InboundPolicy.Verdict verdict;
    HeaderRewriter.Plan rewrite;
    try {
      verdict =
          policy.evaluate(
              new InboundPolicy.Envelope(
                  session.getRemoteAddress().getAddress(),
                  session
                      .getAttachment(
                          SMTPSession.CURRENT_HELO_NAME, ProtocolSession.State.Connection)
                      .orElse(""),
                  sender),
              envelope::open);
      try (InputStream original = envelope.open()) {
        rewrite =
            HeaderRewriter.plan(original, envelope.size(), verdict.fields(), policy::untrusted);
      }
    } catch (IOException | RuntimeException e) {
      LOG.log(System.Logger.Level.ERROR, "policy failed: {0}", e.getClass().getSimpleName());
      metrics.temporaryFailure.increment();
      return TEMPORARY;
    }
    switch (verdict.action()) {
      case REJECT -> {
        metrics.policyRejected.increment();
        return reply(HookReturnCode.deny(), verdict.reply());
      }
      case TEMPFAIL -> {
        metrics.temporaryFailure.increment();
        return reply(HookReturnCode.denySoft(), verdict.reply());
      }
      case JUNK -> metrics.junk.increment();
      case DELIVER -> {}
    }
    SpecialUse folder =
        verdict.action() == InboundPolicy.Action.JUNK ? SpecialUse.JUNK : SpecialUse.INBOX;
    List<RecipientDelivery> recipients = new ArrayList<>();
    for (Transactions.Recipients.Accepted a : accepted) {
      recipients.add(
          new RecipientDelivery(
              a.route(),
              a.address(),
              new DeliveryTarget.Role(folder),
              0,
              List.of(),
              verdict.tags()));
    }
    MessageSource rewritten =
        new MessageSource() {
          @Override
          public InputStream open() throws IOException {
            return rewrite.apply(envelope.open());
          }

          @Override
          public long size() {
            return rewrite.size();
          }
        };
    List<RecipientOutcome> outcomes;
    try {
      outcomes =
          delivery.deliver(
              new DeliveryRequest(ids.next(), recipients, rewritten, clock.millis(), sender));
    } catch (RuntimeException e) {
      LOG.log(System.Logger.Level.ERROR, "delivery failed: {0}", e.getClass().getSimpleName());
      metrics.temporaryFailure.increment();
      return TEMPORARY;
    }
    return reply(outcomes);
  }

  /** A policy reply such as {@code "550 5.7.1 text"}. */
  private static HookResult reply(HookReturnCode code, String reply) {
    return result(code, reply.substring(0, 3), reply.substring(4));
  }

  private HookResult reply(List<RecipientOutcome> outcomes) {
    boolean temporary = false;
    boolean quota = false;
    boolean permanent = false;
    for (RecipientOutcome outcome : outcomes) {
      if (outcome instanceof RecipientOutcome.Failed failed) {
        if (failed.permanent()) {
          permanent = true;
        } else if (failed.reason() == RecipientOutcome.Reason.QUOTA_EXCEEDED) {
          quota = true;
        } else {
          temporary = true;
        }
      }
    }
    if (temporary || quota) {
      metrics.temporaryFailure.increment();
      return temporary ? TEMPORARY : MAILBOX_FULL;
    }
    if (permanent) {
      metrics.oversized.increment();
      return TOO_BIG;
    }
    metrics.accepted.increment();
    return ACCEPTED;
  }
}
