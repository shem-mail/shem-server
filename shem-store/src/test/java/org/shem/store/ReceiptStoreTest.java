package org.shem.store;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.shem.common.FaultInjector;
import org.shem.common.IdGenerator;
import org.shem.common.OpaqueId;
import org.shem.crypto.MailboxPrivateKey;
import org.shem.crypto.SymmetricKey;

class ReceiptStoreTest {
  private static final SecureRandom RANDOM = new SecureRandom();
  @TempDir Path dir;
  private final OpaqueId mailbox = OpaqueId.random(RANDOM);

  private ReceiptStore store(Clock clock) {
    return new ReceiptStore(
        new MailboxPaths(dir), IdGenerator.secure(RANDOM), RANDOM, clock, FaultInjector.NONE);
  }

  private Receipt receipt(SymmetricKey key) {
    return new Receipt(
        OpaqueId.random(RANDOM),
        OpaqueId.random(RANDOM),
        key,
        1234,
        5678,
        1,
        List.of("$label"),
        new DeliveryTarget.Role(SpecialUse.JUNK),
        "marker-sender@example.org",
        "marker-rcpt@example.org",
        List.of("spam"));
  }

  @Test
  void sealsToPublicKeyAndOpensWithPrivateKeyInOrder() throws Exception {
    try (MailboxPrivateKey key = MailboxPrivateKey.generate(1);
        SymmetricKey content = SymmetricKey.generate(RANDOM)) {
      ReceiptStore first = store(Clock.fixed(Instant.ofEpochMilli(1000), ZoneOffset.UTC));
      ReceiptStore second = store(Clock.fixed(Instant.ofEpochMilli(2000), ZoneOffset.UTC));
      Receipt written = receipt(content);
      ReceiptStore.PendingReceipt later = second.write(mailbox, key.publicKey(), receipt(content));
      ReceiptStore.PendingReceipt earlier = first.write(mailbox, key.publicKey(), written);
      List<ReceiptStore.PendingReceipt> pending = first.list(mailbox);
      assertThat(pending)
          .extracting(ReceiptStore.PendingReceipt::receiptId)
          .containsExactly(earlier.receiptId(), later.receiptId());
      assertThat(first.keyVersion(earlier)).isEqualTo(1);
      try (Receipt opened =
          first.open(mailbox, earlier, v -> v == 1 ? Optional.of(key) : Optional.empty())) {
        assertThat(opened.deliveryId()).isEqualTo(written.deliveryId());
        assertThat(opened.target()).isEqualTo(new DeliveryTarget.Role(SpecialUse.JUNK));
        assertThat(opened.recipient()).isEqualTo("marker-rcpt@example.org");
        assertThat(opened.keywords()).containsExactly("$label");
      }
      PlaintextScan.assertNoMarkers(dir, "marker", "example.org", "$label", "spam");
      first.retire(earlier);
      assertThat(first.list(mailbox)).hasSize(1);
    }
  }

  @Test
  void wrongKeyMissingKeyAndTamperingAreCorruption() throws Exception {
    try (MailboxPrivateKey key = MailboxPrivateKey.generate(1);
        MailboxPrivateKey other = MailboxPrivateKey.generate(1);
        SymmetricKey content = SymmetricKey.generate(RANDOM)) {
      ReceiptStore store = store(Clock.systemUTC());
      ReceiptStore.PendingReceipt pending = store.write(mailbox, key.publicKey(), receipt(content));
      assertThatThrownBy(() -> store.open(mailbox, pending, v -> Optional.of(other)))
          .extracting(e -> ((StorageException) e).kind())
          .isEqualTo(StorageException.Kind.CORRUPT);
      assertThatThrownBy(() -> store.open(mailbox, pending, v -> Optional.empty()))
          .extracting(e -> ((StorageException) e).kind())
          .isEqualTo(StorageException.Kind.CORRUPT);
      byte[] data = Files.readAllBytes(pending.file());
      data[data.length - 5] ^= 1;
      Files.write(pending.file(), data);
      assertThatThrownBy(() -> store.open(mailbox, pending, v -> Optional.of(key)))
          .extracting(e -> ((StorageException) e).kind())
          .isEqualTo(StorageException.Kind.CORRUPT);
    }
  }

  @Test
  void receiptCopiedToAnotherMailboxFails() throws Exception {
    try (MailboxPrivateKey key = MailboxPrivateKey.generate(1);
        SymmetricKey content = SymmetricKey.generate(RANDOM)) {
      ReceiptStore store = store(Clock.systemUTC());
      ReceiptStore.PendingReceipt pending = store.write(mailbox, key.publicKey(), receipt(content));
      OpaqueId otherMailbox = OpaqueId.random(RANDOM);
      assertThatThrownBy(() -> store.open(otherMailbox, pending, v -> Optional.of(key)))
          .isInstanceOf(StorageException.class);
    }
  }
}
