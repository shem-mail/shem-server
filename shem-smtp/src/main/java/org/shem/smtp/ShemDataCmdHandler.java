package org.shem.smtp;

import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.List;
import org.apache.james.core.MailAddress;
import org.apache.james.core.MaybeSender;
import org.apache.james.metrics.api.MetricFactory;
import org.apache.james.protocols.api.ProtocolSession;
import org.apache.james.protocols.api.Response;
import org.apache.james.protocols.smtp.MailEnvelope;
import org.apache.james.protocols.smtp.SMTPSession;
import org.apache.james.protocols.smtp.core.DataCmdHandler;

/** DATA with a {@link SpoolingEnvelope} in place of James's unbounded in-memory envelope. */
@SuppressWarnings({"unchecked", "rawtypes"}) // inherited raw getMarkerInterfaces() from James
final class ShemDataCmdHandler extends DataCmdHandler {
  /** Room for the trace headers Shem prepends on top of the client's message. */
  static final long TRACE_ALLOWANCE = 4096;

  private final InboundSettings settings;
  private final SecureRandom random;

  ShemDataCmdHandler(MetricFactory metrics, InboundSettings settings, SecureRandom random) {
    super(metrics);
    this.settings = settings;
    this.random = random;
  }

  @Override
  protected Response doDATA(SMTPSession session, String argument) {
    Response response = super.doDATA(session, argument);
    session
        .getAttachment(MAILENV, ProtocolSession.State.Transaction)
        .filter(SpoolingEnvelope.class::isInstance)
        .map(SpoolingEnvelope.class::cast)
        .ifPresent(envelope -> Transactions.track(session, envelope));
    return response;
  }

  @Override
  protected MailEnvelope createEnvelope(MaybeSender sender, List<MailAddress> recipients) {
    Path spool = settings.spoolDirectory();
    return new SpoolingEnvelope(
        sender,
        recipients,
        settings.maxMessageBytes() + TRACE_ALLOWANCE,
        settings.memoryThresholdBytes(),
        spool,
        random);
  }
}
