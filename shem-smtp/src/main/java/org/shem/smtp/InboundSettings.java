package org.shem.smtp;

import java.net.InetSocketAddress;
import java.nio.file.Path;

/**
 * Inbound listener limits.
 *
 * @param maxMessageBytes largest message accepted from the client, before trace headers
 * @param memoryThresholdBytes messages larger than this are spooled to encrypted provisional files
 * @param maxRecipients accepted RCPT commands per transaction
 * @param maxUnknownRecipients rejected unknown recipients per connection before disconnecting
 * @param spoolDirectory private directory for encrypted provisional files; swept at start
 */
public record InboundSettings(
    InetSocketAddress bind,
    String hostName,
    int maxConnections,
    int maxConnectionsPerIp,
    int timeoutSeconds,
    long maxMessageBytes,
    int memoryThresholdBytes,
    int maxRecipients,
    int maxUnknownRecipients,
    Path spoolDirectory) {
  public InboundSettings {
    if (maxMessageBytes <= 0 || memoryThresholdBytes < 0 || maxRecipients <= 0) {
      throw new IllegalArgumentException("invalid SMTP limits");
    }
    if (maxUnknownRecipients < 0 || maxConnections <= 0 || maxConnectionsPerIp <= 0) {
      throw new IllegalArgumentException("invalid SMTP limits");
    }
  }
}
