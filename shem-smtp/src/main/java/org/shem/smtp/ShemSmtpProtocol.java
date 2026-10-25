package org.shem.smtp;

import org.apache.james.protocols.api.ProtocolSession;
import org.apache.james.protocols.api.ProtocolTransport;
import org.apache.james.protocols.api.Response;
import org.apache.james.protocols.api.handler.ProtocolHandlerChain;
import org.apache.james.protocols.smtp.SMTPConfiguration;
import org.apache.james.protocols.smtp.SMTPProtocol;
import org.apache.james.protocols.smtp.SMTPResponse;
import org.apache.james.protocols.smtp.SMTPRetCode;
import org.apache.james.protocols.smtp.SMTPSessionImpl;

/**
 * SMTP sessions whose overlong-line response ends the connection. James's framer drops an overlong
 * line and continues; inside DATA that would silently truncate the message and could still end in
 * {@code 250}. Here the session is marked so {@link SizeLimit} discards the rest of the
 * transaction, and the connection is closed after the reply.
 */
final class ShemSmtpProtocol extends SMTPProtocol {
  private static final Response LINE_TOO_LONG;

  static {
    SMTPResponse response =
        new SMTPResponse(
            SMTPRetCode.SYNTAX_ERROR_COMMAND_UNRECOGNIZED,
            "5.5.2 Line too long, closing connection");
    response.setEndSession(true);
    LINE_TOO_LONG = response.immutable();
  }

  ShemSmtpProtocol(ProtocolHandlerChain chain, SMTPConfiguration configuration) {
    super(chain, configuration);
  }

  @Override
  public ProtocolSession newSession(ProtocolTransport transport) {
    return new SMTPSessionImpl(transport, (SMTPConfiguration) getConfiguration()) {
      @Override
      public Response newLineTooLongResponse() {
        setAttachment(Transactions.LINE_TOO_LONG, Boolean.TRUE, State.Connection);
        return LINE_TOO_LONG;
      }
    };
  }
}
