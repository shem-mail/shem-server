package org.shem.imap;

import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import org.apache.james.metrics.api.Metric;
import org.apache.james.metrics.api.MetricFactory;
import org.apache.james.metrics.api.TimeMetric;
import org.reactivestreams.Publisher;

/**
 * Minimal James {@link MetricFactory}: aggregate counters keyed by James's fixed metric names
 * (never user data); timers are no-ops.
 */
final class AggregateMetrics implements MetricFactory {
  private final ConcurrentHashMap<String, Counter> counters = new ConcurrentHashMap<>();

  @Override
  public Metric generate(String name) {
    return counters.computeIfAbsent(name, n -> new Counter());
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

  long count(String name) {
    Counter counter = counters.get(name);
    return counter == null ? 0 : counter.getCount();
  }

  private static final class Counter implements Metric {
    private final AtomicLong value = new AtomicLong();

    @Override
    public void increment() {
      value.incrementAndGet();
    }

    @Override
    public void decrement() {
      value.decrementAndGet();
    }

    @Override
    public void add(int n) {
      value.addAndGet(n);
    }

    @Override
    public void remove(int n) {
      value.addAndGet(-n);
    }

    @Override
    public long getCount() {
      return value.get();
    }
  }
}
