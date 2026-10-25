package org.shem.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.shem.common.OpaqueId;

class QuotaLedgerTest {
  @TempDir Path dir;
  private final OpaqueId mailbox = OpaqueId.random(new SecureRandom());

  @Test
  void countsExistingCiphertextAndRejectsOverQuota() throws Exception {
    Path mailboxDir = Files.createDirectories(dir.resolve(mailbox.value()));
    Files.write(mailboxDir.resolve("blob"), new byte[600]);
    QuotaLedger ledger = new QuotaLedger(id -> dir.resolve(id.value()));
    assertThat(ledger.usedBytes(mailbox)).isEqualTo(600);
    try (QuotaLedger.Reservation r = ledger.reserve(mailbox, 300, 1000)) {
      assertThatThrownBy(() -> ledger.reserve(mailbox, 200, 1000))
          .isInstanceOf(QuotaLedger.QuotaExceeded.class);
      r.commit(310);
    }
    assertThat(ledger.usedBytes(mailbox)).isEqualTo(910);
  }

  @Test
  void releasedReservationsFreeOnlyTheirOwnBytes() throws Exception {
    QuotaLedger ledger = new QuotaLedger(id -> dir.resolve(id.value()));
    QuotaLedger.Reservation a = ledger.reserve(mailbox, 400, 1000);
    QuotaLedger.Reservation b = ledger.reserve(mailbox, 400, 1000);
    a.close();
    a.close();
    assertThatThrownBy(() -> ledger.reserve(mailbox, 700, 1000))
        .isInstanceOf(QuotaLedger.QuotaExceeded.class);
    b.commit(400);
    assertThat(ledger.usedBytes(mailbox)).isEqualTo(400);
  }

  @Test
  void concurrentReservationsNeverOverAdmit() throws Exception {
    QuotaLedger ledger = new QuotaLedger(id -> dir.resolve(id.value()));
    AtomicInteger admitted = new AtomicInteger();
    try (ExecutorService pool = Executors.newFixedThreadPool(8)) {
      List<Future<?>> futures = new ArrayList<>();
      for (int i = 0; i < 200; i++) {
        futures.add(
            pool.submit(
                () -> {
                  try {
                    ledger.reserve(mailbox, 10, 1000).commit(10);
                    admitted.incrementAndGet();
                  } catch (QuotaLedger.QuotaExceeded e) {
                    // expected once the quota is full
                  }
                  return null;
                }));
      }
      for (Future<?> f : futures) {
        f.get();
      }
    }
    assertThat(admitted.get()).isEqualTo(100);
    assertThat(ledger.usedBytes(mailbox)).isEqualTo(1000);
  }
}
