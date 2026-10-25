package org.shem.policy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;

class DnsjavaResolverTest {
  @Test
  void unreachableServerIsATemporaryFailureWithinTheTimeout() throws Exception {
    // 192.0.2.1 is TEST-NET-1: never answers.
    DnsjavaResolver resolver =
        new DnsjavaResolver(List.of("192.0.2.1"), Duration.ofMillis(300), 100, Duration.ofHours(1));
    long start = System.nanoTime();
    assertThatThrownBy(() -> resolver.lookup("_dmarc.example.net", DnsResolver.Type.TXT))
        .isInstanceOf(DnsResolver.DnsTemporaryException.class);
    assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofSeconds(5));
  }

  @Test
  void invalidNamesDoNotExist() throws Exception {
    DnsjavaResolver resolver =
        new DnsjavaResolver(List.of("192.0.2.1"), Duration.ofMillis(300), 100, Duration.ofHours(1));
    assertThat(resolver.lookup("bad..name", DnsResolver.Type.TXT)).isEmpty();
  }
}
