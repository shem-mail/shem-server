package org.shem.delivery;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.shem.common.FaultInjector;
import org.shem.common.IdGenerator;
import org.shem.common.OpaqueId;
import org.shem.crypto.MailboxPrivateKey;
import org.shem.identity.QuotaLedger;
import org.shem.identity.RecipientRoute;
import org.shem.store.BlobStore;
import org.shem.store.DeliveryTarget;
import org.shem.store.MailboxPaths;
import org.shem.store.Receipt;
import org.shem.store.ReceiptStore;
import org.shem.store.SpecialUse;

class DeliveryServiceTest {
  private static final SecureRandom RANDOM = new SecureRandom();
  private static final byte[] MESSAGE =
      "From: a@example.org\r\nSubject: DELIVERY-MARKER\r\n\r\nbody DELIVERY-MARKER\r\n"
          .getBytes(StandardCharsets.US_ASCII);
  @TempDir Path dir;

  private DeliveryService service(FaultInjector faults, List<OpaqueId> notified) {
    MailboxPaths paths = new MailboxPaths(dir);
    IdGenerator ids = IdGenerator.secure(RANDOM);
    return new DeliveryService(
        new BlobStore(paths, ids, RANDOM, faults),
        new ReceiptStore(paths, ids, RANDOM, Clock.systemUTC(), faults),
        new QuotaLedger(paths::mailbox),
        notified::add,
        1 << 20);
  }

  private static RecipientDelivery to(RecipientRoute route) {
    return new RecipientDelivery(
        route,
        "rcpt@example.org",
        new DeliveryTarget.Role(SpecialUse.INBOX),
        0,
        List.of(),
        List.of());
  }

  @Test
  void deliversToLockedMailboxesWithOnlyPublicKeys() throws Exception {
    try (MailboxPrivateKey alice = MailboxPrivateKey.generate(1);
        MailboxPrivateKey bob = MailboxPrivateKey.generate(1)) {
      RecipientRoute a = new RecipientRoute(OpaqueId.random(RANDOM), alice.publicKey(), 0);
      RecipientRoute b = new RecipientRoute(OpaqueId.random(RANDOM), bob.publicKey(), 0);
      List<OpaqueId> notified = new java.util.ArrayList<>();
      DeliveryService service = service(FaultInjector.NONE, notified);
      List<RecipientOutcome> outcomes =
          service.deliver(
              new DeliveryRequest(
                  OpaqueId.random(RANDOM),
                  List.of(to(a), to(b)),
                  MessageSource.ofBytes(MESSAGE),
                  0,
                  "sender@example.org"));
      assertThat(outcomes).allMatch(o -> o instanceof RecipientOutcome.Delivered);
      assertThat(notified).containsExactly(a.mailboxId(), b.mailboxId());

      // Only the private key can recover the message, through the receipt.
      MailboxPaths paths = new MailboxPaths(dir);
      ReceiptStore receipts =
          new ReceiptStore(
              paths, IdGenerator.secure(RANDOM), RANDOM, Clock.systemUTC(), FaultInjector.NONE);
      ReceiptStore.PendingReceipt pending = receipts.list(a.mailboxId()).get(0);
      try (Receipt receipt = receipts.open(a.mailboxId(), pending, v -> Optional.of(alice));
          InputStream in =
              new BlobStore(paths, IdGenerator.secure(RANDOM), RANDOM, FaultInjector.NONE)
                  .open(a.mailboxId(), receipt.blobId(), receipt.contentKey())) {
        assertThat(in.readAllBytes()).isEqualTo(MESSAGE);
        assertThat(receipt.deliveryId())
            .isEqualTo(((RecipientOutcome.Delivered) outcomes.get(0)).deliveryId());
      }
      assertNoMarker(dir, "DELIVERY-MARKER");
      assertNoMarker(dir, "rcpt@example.org");
    }
  }

  @Test
  void quotaAndSizeFailuresAreReportedPerRecipient() throws Exception {
    try (MailboxPrivateKey key = MailboxPrivateKey.generate(1)) {
      RecipientRoute tiny = new RecipientRoute(OpaqueId.random(RANDOM), key.publicKey(), 100);
      RecipientRoute roomy = new RecipientRoute(OpaqueId.random(RANDOM), key.publicKey(), 0);
      List<RecipientOutcome> outcomes =
          service(FaultInjector.NONE, new java.util.ArrayList<>())
              .deliver(
                  new DeliveryRequest(
                      OpaqueId.random(RANDOM),
                      List.of(to(tiny), to(roomy)),
                      MessageSource.ofBytes(MESSAGE),
                      0,
                      ""));
      assertThat(outcomes.get(0))
          .isEqualTo(
              new RecipientOutcome.Failed(
                  tiny.mailboxId(), RecipientOutcome.Reason.QUOTA_EXCEEDED));
      assertThat(outcomes.get(1)).isInstanceOf(RecipientOutcome.Delivered.class);
      assertThat(
              new BlobStore(
                      new MailboxPaths(dir), IdGenerator.secure(RANDOM), RANDOM, FaultInjector.NONE)
                  .list(tiny.mailboxId()))
          .isEmpty();
    }
  }

  @Test
  void diskFullBeforeReceiptNeverReportsSuccess() throws Exception {
    try (MailboxPrivateKey key = MailboxPrivateKey.generate(1)) {
      RecipientRoute route = new RecipientRoute(OpaqueId.random(RANDOM), key.publicKey(), 0);
      FaultInjector diskFull =
          point -> {
            if (point.equals(ReceiptStore.FAULT_BEFORE_PUBLISH)) {
              throw new IOException("No space left on device");
            }
          };
      List<RecipientOutcome> outcomes =
          service(diskFull, new java.util.ArrayList<>())
              .deliver(
                  new DeliveryRequest(
                      OpaqueId.random(RANDOM),
                      List.of(to(route)),
                      MessageSource.ofBytes(MESSAGE),
                      0,
                      ""));
      assertThat(outcomes)
          .containsExactly(
              new RecipientOutcome.Failed(
                  route.mailboxId(), RecipientOutcome.Reason.STORAGE_UNAVAILABLE));
      MailboxPaths paths = new MailboxPaths(dir);
      assertThat(
              new ReceiptStore(
                      paths,
                      IdGenerator.secure(RANDOM),
                      RANDOM,
                      Clock.systemUTC(),
                      FaultInjector.NONE)
                  .list(route.mailboxId()))
          .isEmpty();
    }
  }

  @Test
  void encryptedSpoolHoldsOnlyCiphertextAndIsDeletedOnClose() throws Exception {
    Path spoolDir = dir.resolve("spool");
    EncryptedSpool spool = EncryptedSpool.create(spoolDir, RANDOM);
    spool.fill(new ByteArrayInputStream(MESSAGE), 1 << 20);
    assertNoMarker(spoolDir, "DELIVERY-MARKER");
    try (InputStream in = spool.open()) {
      assertThat(in.readAllBytes()).isEqualTo(MESSAGE);
    }
    spool.close();
    try (var files = Files.list(spoolDir)) {
      assertThat(files.count()).isZero();
    }
  }

  private static void assertNoMarker(Path root, String marker) throws IOException {
    byte[] needle = marker.getBytes(StandardCharsets.UTF_8);
    try (var files = Files.walk(root)) {
      for (Path file : (Iterable<Path>) files::iterator) {
        if (Files.isRegularFile(file)) {
          String content = new String(Files.readAllBytes(file), StandardCharsets.ISO_8859_1);
          assertThat(content).doesNotContain(new String(needle, StandardCharsets.ISO_8859_1));
        }
      }
    }
  }
}
