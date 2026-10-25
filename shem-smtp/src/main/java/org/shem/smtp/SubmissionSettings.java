package org.shem.smtp;

import java.net.InetSocketAddress;
import java.nio.file.Path;
import org.jspecify.annotations.Nullable;

/**
 * Submission listeners and limits.
 *
 * @param implicitTls port 465 listener (TLS from the first byte), if any
 * @param startTls port 587 listener (STARTTLS required before AUTH), if any
 * @param recipientsPerHour accepted recipients per account per hour
 */
public record SubmissionSettings(
    @Nullable InetSocketAddress implicitTls,
    @Nullable InetSocketAddress startTls,
    String hostName,
    int maxConnections,
    int maxConnectionsPerIp,
    int timeoutSeconds,
    long maxMessageBytes,
    int memoryThresholdBytes,
    int maxRecipients,
    int recipientsPerHour,
    Path spoolDirectory) {
  public SubmissionSettings {
    if (implicitTls == null && startTls == null) {
      throw new IllegalArgumentException("submission needs at least one listener");
    }
    if (maxRecipients <= 0 || recipientsPerHour <= 0 || maxMessageBytes <= 0) {
      throw new IllegalArgumentException("invalid submission limits");
    }
  }

  /** The DATA limits shared with inbound handling. */
  InboundSettings data(InetSocketAddress bind) {
    return new InboundSettings(
        bind,
        hostName,
        maxConnections,
        maxConnectionsPerIp,
        timeoutSeconds,
        maxMessageBytes,
        memoryThresholdBytes,
        maxRecipients,
        0,
        spoolDirectory);
  }
}
