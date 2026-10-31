package org.shem.common;

import java.io.IOException;

/**
 * Named failure points at durability boundaries. Production uses {@link #NONE}; tests throw from
 * selected points to simulate crashes ({@link SimulatedCrash}) or I/O errors such as a full disk.
 */
@FunctionalInterface
public interface FaultInjector {
  FaultInjector NONE = point -> {};

  void at(String point) throws IOException;

  /** Unchecked stand-in for an abrupt process stop; never thrown in production. */
  final class SimulatedCrash extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public SimulatedCrash(String point) {
      super("simulated crash at " + point);
    }
  }
}
