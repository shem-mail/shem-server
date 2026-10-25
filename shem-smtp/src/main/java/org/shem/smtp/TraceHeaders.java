package org.shem.smtp;

import java.time.Clock;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import org.apache.james.core.MailAddress;
import org.apache.james.protocols.api.ProtocolSession;
import org.apache.james.protocols.smtp.SMTPSession;
import org.apache.james.protocols.smtp.core.ReceivedDataLineFilter;

/**
 * Prepends {@code Return-Path} and {@code Received} (RFC 5321 section 4.4) as the final delivery
 * MTA. Unlike James's generator it performs no reverse DNS lookup, never names a recipient, and
 * uses the injected clock. Both headers end up only inside the encrypted message.
 */
final class TraceHeaders extends ReceivedDataLineFilter {
  private static final DateTimeFormatter DATE =
      DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss Z", Locale.US);
  private final String hostName;
  private final Clock clock;

  TraceHeaders(String hostName, Clock clock) {
    this.hostName = hostName;
    this.clock = clock;
  }

  @Override
  protected Collection<Header> headers(SMTPSession session) {
    String sender =
        session
            .getAttachment(SMTPSession.SENDER, ProtocolSession.State.Transaction)
            .flatMap(s -> s.asOptional().map(MailAddress::asString))
            .orElse("");
    String helo =
        session
            .getAttachment(SMTPSession.CURRENT_HELO_NAME, ProtocolSession.State.Connection)
            .orElse("unknown");
    boolean ehlo =
        session
            .getAttachment(SMTPSession.CURRENT_HELO_MODE, ProtocolSession.State.Connection)
            .filter("EHLO"::equals)
            .isPresent();
    String protocol = !ehlo ? "SMTP" : session.isTLSStarted() ? "ESMTPS" : "ESMTP";
    Header received =
        new Header(
            "Received",
            "from "
                + helo
                + " (["
                + session.getRemoteAddress().getAddress().getHostAddress()
                + "])");
    received.add("by " + hostName + " (Shem) with " + protocol + ";");
    received.add(DATE.format(ZonedDateTime.now(clock)));
    return List.of(new Header("Return-Path", "<" + sender + ">"), received);
  }
}
