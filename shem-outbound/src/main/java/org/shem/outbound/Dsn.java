package org.shem.outbound;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Locale;

/**
 * Builds an RFC 3464 delivery status notification for failed recipients. Only the original header
 * section is returned (at most {@link #MAX_HEADERS} bytes, as {@code text/rfc822-headers}); the
 * body is never echoed.
 */
final class Dsn {
  static final int MAX_HEADERS = 64 * 1024;
  private static final DateTimeFormatter DATE =
      DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss Z", Locale.US)
          .withZone(ZoneOffset.UTC);

  private Dsn() {}

  static byte[] build(
      String hostName,
      String boundary,
      QueueItem item,
      List<QueueItem.Recipient> failed,
      InputStream original,
      Instant now)
      throws IOException {
    StringBuilder text = new StringBuilder();
    text.append("From: Mail Delivery System <MAILER-DAEMON@").append(hostName).append(">\r\n");
    text.append("To: <").append(item.sender()).append(">\r\n");
    text.append("Subject: Undelivered Mail Returned to Sender\r\n");
    text.append("Date: ").append(DATE.format(now)).append("\r\n");
    text.append("Message-ID: <").append(boundary).append('@').append(hostName).append(">\r\n");
    text.append("Auto-Submitted: auto-replied\r\nMIME-Version: 1.0\r\n");
    text.append("Content-Type: multipart/report; report-type=delivery-status;\r\n\tboundary=\"")
        .append(boundary)
        .append("\"\r\n\r\n");
    text.append("--")
        .append(boundary)
        .append("\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n");
    text.append("Your message could not be delivered to the following recipients:\r\n\r\n");
    for (QueueItem.Recipient r : failed) {
      text.append("  ")
          .append(r.address())
          .append(": ")
          .append(explain(r.lastReply()))
          .append("\r\n");
    }
    text.append("\r\n--")
        .append(boundary)
        .append("\r\nContent-Type: message/delivery-status\r\n\r\n");
    text.append("Reporting-MTA: dns; ").append(hostName).append("\r\n");
    text.append("Arrival-Date: ").append(DATE.format(item.created())).append("\r\n");
    for (QueueItem.Recipient r : failed) {
      text.append("\r\nFinal-Recipient: rfc822; ").append(r.address()).append("\r\n");
      text.append("Action: failed\r\n");
      text.append("Status: ").append(status(r.lastReply())).append("\r\n");
      if (r.lastReply().matches("\\d{3}( .*)?")) {
        text.append("Diagnostic-Code: smtp; ").append(r.lastReply()).append("\r\n");
      }
    }
    text.append("\r\n--").append(boundary).append("\r\nContent-Type: text/rfc822-headers\r\n\r\n");
    StringBuilder headers = new StringBuilder();
    byte[] bytes = original.readNBytes(MAX_HEADERS);
    String head = new String(bytes, StandardCharsets.UTF_8);
    int end = head.indexOf("\r\n\r\n");
    headers.append(end < 0 ? head : head.substring(0, end + 2));
    text.append(headers);
    text.append("\r\n--").append(boundary).append("--\r\n");
    return text.toString().getBytes(StandardCharsets.UTF_8);
  }

  /** The RFC 3463 status for a stored reply summary or local reason code. */
  static String status(String reply) {
    String[] parts = reply.split(" ", -1);
    if (parts.length >= 2 && parts[1].matches("[45]\\.\\d{1,3}\\.\\d{1,3}")) {
      return parts[1].charAt(0) == '4' ? "5" + parts[1].substring(1) : parts[1];
    }
    return switch (reply) {
      case "expired" -> "4.4.7";
      case "null-mx" -> "5.1.10";
      case "no-route" -> "5.4.4";
      default -> reply.startsWith("5") ? "5.0.0" : "4.0.0";
    };
  }

  private static String explain(String reply) {
    return switch (reply) {
      case "expired" -> "delivery was not possible before the message expired";
      case "null-mx" -> "the recipient domain does not accept mail";
      case "no-route" -> "no mail server could be found for the recipient domain";
      default -> "the recipient's server rejected the message (" + reply + ")";
    };
  }
}
