package org.shem.outbound;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.shem.common.OpaqueId;

/**
 * Persistent state of one queued message: envelope, per-recipient delivery state, and schedule.
 * Immutable; the queue stores a new version for every transition.
 *
 * @param sender envelope sender ({@code ""} for the null reverse path, used by DSNs)
 */
public record QueueItem(
    OpaqueId id,
    String sender,
    List<Recipient> recipients,
    Instant created,
    Instant expires,
    Instant nextAttempt,
    int attempts,
    boolean notified) {
  public QueueItem {
    recipients = List.copyOf(recipients);
  }

  /** Delivery state of one recipient. */
  public enum Status {
    PENDING,
    DELIVERED,
    FAILED
  }

  /**
   * One envelope recipient.
   *
   * @param lastReply the last SMTP reply code and enhanced status (for example {@code "550
   *     5.1.1"}), or a local reason code; never a full transcript
   */
  public record Recipient(String address, Status status, String lastReply) {}

  public List<Recipient> pending() {
    return recipients.stream().filter(r -> r.status() == Status.PENDING).toList();
  }

  public List<Recipient> failed() {
    return recipients.stream().filter(r -> r.status() == Status.FAILED).toList();
  }

  /** A copy with the given recipients' states replaced (matched by address). */
  public QueueItem withRecipients(List<Recipient> updates) {
    List<Recipient> next = new ArrayList<>();
    for (Recipient current : recipients) {
      Recipient replacement = current;
      for (Recipient update : updates) {
        if (update.address().equals(current.address())) {
          replacement = update;
        }
      }
      next.add(replacement);
    }
    return new QueueItem(id, sender, next, created, expires, nextAttempt, attempts, notified);
  }

  public QueueItem rescheduled(Instant next, int attemptCount) {
    return new QueueItem(id, sender, recipients, created, expires, next, attemptCount, notified);
  }

  public QueueItem markNotified() {
    return new QueueItem(id, sender, recipients, created, expires, nextAttempt, attempts, true);
  }
}
