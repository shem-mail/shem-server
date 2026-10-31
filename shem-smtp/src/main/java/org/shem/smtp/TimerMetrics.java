package org.shem.smtp;

import java.time.Duration;
import org.apache.james.metrics.api.Metric;
import org.apache.james.metrics.api.MetricFactory;
import org.apache.james.metrics.api.TimeMetric;
import org.reactivestreams.Publisher;

/** Discards James's per-command metrics; Shem exposes its own {@link InboundMetrics}. */
final class TimerMetrics implements MetricFactory {
  private static final Metric NONE =
      new Metric() {
        @Override
        public void increment() {}

        @Override
        public void decrement() {}

        @Override
        public void add(int value) {}

        @Override
        public void remove(int value) {}

        @Override
        public long getCount() {
          return 0;
        }
      };

  @Override
  public Metric generate(String name) {
    return NONE;
  }

  @Override
  public TimeMetric timer(String name) {
    long start = System.nanoTime();
    return new TimeMetric() {
      @Override
      public String name() {
        return name;
      }

      @Override
      public ExecutionResult stopAndPublish() {
        Duration elapsed = Duration.ofNanos(System.nanoTime() - start);
        return new ExecutionResult() {
          @Override
          public Duration elasped() {
            return elapsed;
          }

          @Override
          @SuppressWarnings("deprecation") // required by the James interface
          public ExecutionResult logWhenExceedP99(Duration threshold) {
            return this;
          }
        };
      }

      @Override
      public void record(Duration duration) {}
    };
  }

  @Override
  public <T> Publisher<T> decoratePublisherWithTimerMetric(String name, Publisher<T> publisher) {
    return publisher;
  }

  @Override
  @SuppressWarnings("deprecation") // required by the James interface
  public <T> Publisher<T> decoratePublisherWithTimerMetricLogP99(
      String name, Publisher<T> publisher) {
    return publisher;
  }
}
