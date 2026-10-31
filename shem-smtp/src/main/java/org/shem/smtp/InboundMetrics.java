package org.shem.smtp;

import java.util.concurrent.atomic.LongAdder;

/** Aggregate inbound counters. Reason codes only; never addresses or message identifiers. */
public final class InboundMetrics {
  final LongAdder accepted = new LongAdder();
  final LongAdder relayDenied = new LongAdder();
  final LongAdder unknownRecipient = new LongAdder();
  final LongAdder tooManyRecipients = new LongAdder();
  final LongAdder oversized = new LongAdder();
  final LongAdder temporaryFailure = new LongAdder();
  final LongAdder spooled = new LongAdder();
  final LongAdder greylisted = new LongAdder();
  final LongAdder junk = new LongAdder();
  final LongAdder policyRejected = new LongAdder();

  public long accepted() {
    return accepted.sum();
  }

  public long relayDenied() {
    return relayDenied.sum();
  }

  public long unknownRecipient() {
    return unknownRecipient.sum();
  }

  public long tooManyRecipients() {
    return tooManyRecipients.sum();
  }

  public long oversized() {
    return oversized.sum();
  }

  public long temporaryFailure() {
    return temporaryFailure.sum();
  }

  public long spooled() {
    return spooled.sum();
  }

  public long greylisted() {
    return greylisted.sum();
  }

  public long junk() {
    return junk.sum();
  }

  public long policyRejected() {
    return policyRejected.sum();
  }
}
