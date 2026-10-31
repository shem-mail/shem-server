package org.shem.crypto;

/**
 * Argon2id cost parameters. Stored parameters are validated against {@link Limits} before any
 * memory is allocated, so a tampered slot cannot request unbounded work.
 */
public record Argon2Parameters(int memoryKiB, int iterations, int parallelism) {
  /** Proposed default; Phase 0 benchmark evidence lives in docs/adr/0003-argon2id-budget.md. */
  public static final Argon2Parameters DEFAULT = new Argon2Parameters(64 * 1024, 3, 1);

  public Argon2Parameters {
    if (memoryKiB < 8 * parallelism || iterations < 1 || parallelism < 1) {
      throw new IllegalArgumentException("invalid Argon2id parameters");
    }
  }

  /** Bounds accepted from persisted slots. */
  public record Limits(int minMemoryKiB, int maxMemoryKiB, int maxIterations, int maxParallelism) {
    public static final Limits DEFAULT = new Limits(19 * 1024, 1024 * 1024, 10, 8);

    public boolean accepts(Argon2Parameters parameters) {
      return parameters.memoryKiB() >= minMemoryKiB
          && parameters.memoryKiB() <= maxMemoryKiB
          && parameters.iterations() <= maxIterations
          && parameters.parallelism() <= maxParallelism;
    }
  }
}
