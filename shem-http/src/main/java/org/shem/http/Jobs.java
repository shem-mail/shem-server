package org.shem.http;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import org.jspecify.annotations.Nullable;
import org.shem.common.OpaqueId;

/**
 * Background jobs started through the API (ADR 0017): currently key rotations. In memory only; a
 * job's inputs (the re-proved password) never outlive its run, and an interrupted rotation is
 * completed by {@code KeyLifecycle.resume} at the mailbox's next unlock, so nothing needs to be
 * persisted to resume it. Jobs are visible only to their owning mailbox.
 */
final class Jobs implements AutoCloseable {
  static final int MAX_JOBS = 256;
  static final Duration RETENTION = Duration.ofHours(1);
  static final int MAX_RUNNING = 2;

  /** Job state as reported to the owner. */
  enum Status {
    RUNNING,
    SUCCEEDED,
    FAILED,
    /** The lease ended mid-run; the work completes at the next unlock. */
    INTERRUPTED
  }

  /** A job and its sanitized progress. */
  static final class Job {
    final OpaqueId id;
    final OpaqueId owner;
    final String type;
    final @Nullable String idempotencyKey;
    final Instant created;
    volatile Status status = Status.RUNNING;
    volatile @Nullable Instant finished;
    volatile @Nullable String detail;

    Job(OpaqueId id, OpaqueId owner, String type, @Nullable String idempotencyKey, Instant now) {
      this.id = id;
      this.owner = owner;
      this.type = type;
      this.idempotencyKey = idempotencyKey;
      this.created = now;
    }
  }

  /** The work of a job; returns normally on success. */
  @FunctionalInterface
  interface Work {
    void run(Job job) throws Exception;
  }

  /** Thrown when a job cannot be accepted now. */
  static final class Busy extends Exception {
    private static final long serialVersionUID = 1L;

    Busy(String message) {
      super(message);
    }
  }

  private final Clock clock;
  private final SecureRandom random;
  private final Map<OpaqueId, Job> jobs = new LinkedHashMap<>();
  private final ThreadPoolExecutor executor =
      new ThreadPoolExecutor(
          MAX_RUNNING,
          MAX_RUNNING,
          30,
          TimeUnit.SECONDS,
          new ArrayBlockingQueue<>(MAX_RUNNING * 4),
          Thread.ofVirtual().name("shem-job-", 0).factory());

  Jobs(Clock clock, SecureRandom random) {
    this.clock = clock;
    this.random = random;
  }

  /**
   * Starts a job for {@code owner}, or returns the existing one for the same idempotency key. At
   * most one job of a type runs per owner.
   */
  synchronized Job start(OpaqueId owner, String type, @Nullable String idempotencyKey, Work work)
      throws Busy {
    sweep();
    for (Job job : jobs.values()) {
      if (job.owner.equals(owner)
          && idempotencyKey != null
          && idempotencyKey.equals(job.idempotencyKey)) {
        if (!job.type.equals(type)) {
          throw new Busy("idempotency key already used");
        }
        return job;
      }
    }
    for (Job job : jobs.values()) {
      if (job.owner.equals(owner) && job.type.equals(type) && job.status == Status.RUNNING) {
        throw new Busy("a job of this type is already running");
      }
    }
    if (jobs.size() >= MAX_JOBS) {
      throw new Busy("too many jobs");
    }
    Job job = new Job(OpaqueId.random(random), owner, type, idempotencyKey, clock.instant());
    try {
      executor.execute(() -> run(job, work));
    } catch (RejectedExecutionException e) {
      throw new Busy("server busy");
    }
    jobs.put(job.id, job);
    return job;
  }

  private void run(Job job, Work work) {
    try {
      work.run(job);
      job.status = Status.SUCCEEDED;
    } catch (org.shem.mailbox.RevokedLeaseException e) {
      job.status = Status.INTERRUPTED;
      job.detail = "session ended; the operation completes at the next login";
    } catch (InterruptedException e) {
      job.status = Status.INTERRUPTED;
      job.detail = "server stopping; the operation completes at the next login";
      Thread.currentThread().interrupt();
    } catch (Exception e) {
      job.status = Status.FAILED;
      if (job.detail == null) {
        job.detail = "operation failed";
      }
    } finally {
      job.finished = clock.instant();
    }
  }

  /** The job if {@code owner} owns it; otherwise empty, exactly as for an unknown id. */
  synchronized Optional<Job> find(OpaqueId id, OpaqueId owner) {
    Job job = jobs.get(id);
    return job != null && job.owner.equals(owner) ? Optional.of(job) : Optional.empty();
  }

  synchronized void sweep() {
    Instant cutoff = clock.instant().minus(RETENTION);
    for (Iterator<Job> it = jobs.values().iterator(); it.hasNext(); ) {
      Instant finished = it.next().finished;
      if (finished != null && finished.isBefore(cutoff)) {
        it.remove();
      }
    }
  }

  @Override
  public void close() {
    executor.shutdownNow();
  }
}
