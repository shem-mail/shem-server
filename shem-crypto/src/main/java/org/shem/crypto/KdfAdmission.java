package org.shem.crypto;

import java.time.Duration;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

/**
 * Global admission control for Argon2id: a fixed memory budget shared by IMAP, submission, and
 * HTTP. Work that cannot be admitted within the wait bound is rejected before any allocation.
 */
public final class KdfAdmission {
  private final Semaphore memoryKiB;
  private final int budgetKiB;
  private final Duration maxWait;

  public KdfAdmission(int budgetKiB, Duration maxWait) {
    if (budgetKiB <= 0) {
      throw new IllegalArgumentException("budget must be positive");
    }
    this.budgetKiB = budgetKiB;
    this.memoryKiB = new Semaphore(budgetKiB, true);
    this.maxWait = maxWait;
  }

  /** Raised when the KDF budget is saturated; protocols map this to a temporary failure. */
  public static final class Rejected extends Exception {
    private static final long serialVersionUID = 1L;

    public Rejected() {
      super("key derivation capacity exhausted");
    }
  }

  /** A held reservation; release by closing. */
  public final class Permit implements AutoCloseable {
    private final int amount;
    private boolean released;

    private Permit(int amount) {
      this.amount = amount;
    }

    @Override
    public void close() {
      if (!released) {
        released = true;
        memoryKiB.release(amount);
      }
    }
  }

  public Permit acquire(Argon2Parameters parameters) throws Rejected, InterruptedException {
    int amount = parameters.memoryKiB();
    if (amount > budgetKiB) {
      throw new Rejected();
    }
    if (!memoryKiB.tryAcquire(amount, maxWait.toNanos(), TimeUnit.NANOSECONDS)) {
      throw new Rejected();
    }
    return new Permit(amount);
  }

  public int availableKiB() {
    return memoryKiB.availablePermits();
  }
}
