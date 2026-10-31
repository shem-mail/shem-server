package org.shem.outbound;

import java.time.Duration;
import java.util.List;
import javax.net.ssl.SSLContext;

/**
 * Outbound delivery settings.
 *
 * @param hostName name used in EHLO and DSNs
 * @param port SMTP port of remote MX hosts (25 except in tests)
 * @param verifiedTls trust for MTA-STS-enforced connections (normally the JDK default)
 * @param retrySchedule delays between attempts; the last entry repeats until expiry
 * @param maxConcurrent simultaneous deliveries
 */
public record OutboundSettings(
    String hostName,
    int port,
    Duration connectTimeout,
    Duration commandTimeout,
    Duration dataTimeout,
    SSLContext verifiedTls,
    List<Duration> retrySchedule,
    int maxConcurrent,
    int maxRecipientsPerTransaction) {
  public OutboundSettings {
    retrySchedule = List.copyOf(retrySchedule);
    if (retrySchedule.isEmpty() || maxConcurrent <= 0 || maxRecipientsPerTransaction <= 0) {
      throw new IllegalArgumentException("invalid outbound settings");
    }
  }

  /** RFC 5321 section 4.5.4.1 suggests at least 30 minutes between retries; start sooner once. */
  public static final List<Duration> DEFAULT_RETRIES =
      List.of(
          Duration.ofMinutes(5),
          Duration.ofMinutes(30),
          Duration.ofHours(1),
          Duration.ofHours(2),
          Duration.ofHours(4));

  Duration delayAfter(int attempts) {
    return retrySchedule.get(Math.min(attempts, retrySchedule.size()) - 1);
  }
}
