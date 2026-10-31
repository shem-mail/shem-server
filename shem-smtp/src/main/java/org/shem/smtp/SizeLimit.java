package org.shem.smtp;

import java.io.IOException;
import java.util.List;
import org.apache.james.protocols.api.ProtocolSession;
import org.apache.james.protocols.api.Response;
import org.apache.james.protocols.api.handler.LineHandler;
import org.apache.james.protocols.smtp.SMTPResponse;
import org.apache.james.protocols.smtp.SMTPRetCode;
import org.apache.james.protocols.smtp.SMTPSession;
import org.apache.james.protocols.smtp.core.DataCmdHandler;
import org.apache.james.protocols.smtp.core.DataLineFilter;
import org.apache.james.protocols.smtp.core.esmtp.EhloExtension;
import org.apache.james.protocols.smtp.hook.HookResult;
import org.apache.james.protocols.smtp.hook.HookReturnCode;
import org.apache.james.protocols.smtp.hook.MailParametersHook;
import org.jspecify.annotations.Nullable;

/**
 * RFC 1870 SIZE: advertises the limit, rejects a declared size above it at MAIL, and enforces it on
 * the DATA stream. Replaces James's {@code MailSizeEsmtpExtension}, which parses SIZE as an {@code
 * int}, logs envelope addresses, and still invokes the message hooks for an oversized message. Once
 * the limit is exceeded, further lines are discarded without buffering and the envelope is wiped;
 * the message hooks never run.
 */
final class SizeLimit implements MailParametersHook, EhloExtension, DataLineFilter {
  private static final String TOO_BIG = "5.3.4 Message size exceeds fixed maximum message size";
  private static final HookResult DECLARED_TOO_BIG =
      HookResult.builder()
          .hookReturnCode(HookReturnCode.deny())
          .smtpReturnCode(SMTPRetCode.QUOTA_EXCEEDED)
          .smtpDescription(TOO_BIG)
          .build();
  private static final HookResult SYNTAX =
      HookResult.builder()
          .hookReturnCode(HookReturnCode.deny())
          .smtpReturnCode(SMTPRetCode.SYNTAX_ERROR_ARGUMENTS)
          .smtpDescription("5.5.4 Invalid SIZE parameter")
          .build();

  private final long maxBytes;
  private final InboundMetrics metrics;

  SizeLimit(long maxBytes, InboundMetrics metrics) {
    this.maxBytes = maxBytes;
    this.metrics = metrics;
  }

  @Override
  public String[] getMailParamNames() {
    return new String[] {"SIZE"};
  }

  @Override
  public HookResult doMailParameter(SMTPSession session, String paramName, String paramValue) {
    long declared;
    try {
      declared = Long.parseLong(paramValue);
    } catch (NumberFormatException e) {
      return SYNTAX;
    }
    if (declared < 0) {
      return SYNTAX;
    }
    if (declared > maxBytes) {
      metrics.oversized.increment();
      return DECLARED_TOO_BIG;
    }
    return HookResult.DECLINED;
  }

  @Override
  public List<String> getImplementedEsmtpFeatures(SMTPSession session) {
    return List.of("SIZE " + maxBytes);
  }

  @Override
  public @Nullable Response onLine(
      SMTPSession session, byte[] line, LineHandler<SMTPSession> next) {
    boolean terminator = line.length == 3 && line[0] == '.';
    if (session
        .getAttachment(Transactions.LINE_TOO_LONG, ProtocolSession.State.Connection)
        .isPresent()) {
      // The connection is closing (ShemSmtpProtocol); the message is incomplete and never
      // delivered.
      discardEnvelope(session);
      return null;
    }
    boolean oversized =
        session
            .getAttachment(Transactions.OVERSIZED, ProtocolSession.State.Transaction)
            .isPresent();
    if (oversized) {
      if (!terminator) {
        return null;
      }
      session.popLineHandler();
      session.resetState();
      return new SMTPResponse(SMTPRetCode.QUOTA_EXCEEDED, TOO_BIG);
    }
    if (terminator) {
      return next.onLine(session, line);
    }
    long total =
        session.getAttachment(Transactions.DATA_BYTES, ProtocolSession.State.Transaction).orElse(0L)
            + line.length;
    session.setAttachment(Transactions.DATA_BYTES, total, ProtocolSession.State.Transaction);
    if (total > maxBytes) {
      metrics.oversized.increment();
      session.setAttachment(
          Transactions.OVERSIZED, Boolean.TRUE, ProtocolSession.State.Transaction);
      discardEnvelope(session);
      return null;
    }
    return next.onLine(session, line);
  }

  private static void discardEnvelope(SMTPSession session) {
    session
        .getAttachment(DataCmdHandler.MAILENV, ProtocolSession.State.Transaction)
        .filter(SpoolingEnvelope.class::isInstance)
        .map(SpoolingEnvelope.class::cast)
        .ifPresent(envelope -> discardQuietly(session, envelope));
  }

  private static void discardQuietly(SMTPSession session, SpoolingEnvelope envelope) {
    try {
      Transactions.discard(session, envelope);
    } catch (IOException e) {
      // The spool key is already wiped, so the leftover file is unreadable ciphertext that the
      // start-up sweep removes; the transaction is rejected either way.
    }
  }
}
