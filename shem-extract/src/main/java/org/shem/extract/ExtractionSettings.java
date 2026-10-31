package org.shem.extract;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

/**
 * Attachment extraction limits and isolation (ADR 0019).
 *
 * @param sandbox command prefix that launches the worker JVM in an OS sandbox (for example {@code
 *     unshare --net ...} or {@code systemd-run ...}); empty runs it directly
 * @param scratch parent of per-worker temp directories; must be a private tmpfs when isolation is
 *     required
 * @param canary a file only the server may read (inside the data directory); the worker must not be
 *     able to read it
 * @param requireIsolation refuse to start unless the probe shows no network, no canary access, and
 *     tmpfs scratch
 */
public record ExtractionSettings(
    List<String> sandbox,
    Path scratch,
    Path canary,
    int workers,
    Duration timeout,
    int maxInputBytes,
    int maxOutputChars,
    int heapMiB,
    int requestsPerWorker,
    boolean requireIsolation) {
  public ExtractionSettings {
    sandbox = List.copyOf(sandbox);
    if (workers < 1 || workers > 16) {
      throw new IllegalArgumentException("extraction.workers must be 1-16");
    }
    if (timeout.isNegative() || timeout.isZero()) {
      throw new IllegalArgumentException("extraction.timeout must be positive");
    }
    if (maxInputBytes < 1024 || maxOutputChars < 1024 || heapMiB < 64 || requestsPerWorker < 1) {
      throw new IllegalArgumentException("extraction limits out of range");
    }
  }
}
