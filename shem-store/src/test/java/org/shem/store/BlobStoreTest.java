package org.shem.store;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.shem.common.FaultInjector;
import org.shem.common.IdGenerator;
import org.shem.common.OpaqueId;
import org.shem.crypto.SymmetricKey;

class BlobStoreTest {
  private static final SecureRandom RANDOM = new SecureRandom();
  @TempDir Path dir;
  private final OpaqueId mailbox = OpaqueId.random(RANDOM);

  private BlobStore store(FaultInjector faults) {
    return new BlobStore(new MailboxPaths(dir), IdGenerator.secure(RANDOM), RANDOM, faults);
  }

  private static byte[] message(int bodyBytes) {
    StringBuilder sb =
        new StringBuilder("From: marker-sender@example.org\r\nSubject: MARKER-SUBJECT\r\n\r\n");
    while (sb.length() < bodyBytes) {
      sb.append("MARKER-BODY line of synthetic text\r\n");
    }
    return sb.toString().getBytes(StandardCharsets.US_ASCII);
  }

  @Test
  void roundTripsAndLeavesNoPlaintextOnDisk() throws Exception {
    byte[] data = message(300_000);
    BlobStore.WrittenBlob blob =
        store(FaultInjector.NONE).write(mailbox, new ByteArrayInputStream(data), 1 << 20);
    try (SymmetricKey key = blob.contentKey();
        InputStream in = store(FaultInjector.NONE).open(mailbox, blob.blobId(), key)) {
      assertThat(in.readAllBytes()).isEqualTo(data);
    }
    assertThat(blob.plaintextBytes()).isEqualTo(data.length);
    PlaintextScan.assertNoMarkers(dir, "MARKER", "marker-sender", "example.org");
  }

  @Test
  void rangeReadsUseSeekableDecryption() throws Exception {
    byte[] data = message(500_000);
    BlobStore store = store(FaultInjector.NONE);
    BlobStore.WrittenBlob blob = store.write(mailbox, new ByteArrayInputStream(data), 1 << 20);
    try (SymmetricKey key = blob.contentKey();
        SeekableByteChannel channel = store.openSeekable(mailbox, blob.blobId(), key)) {
      assertThat(channel.size()).isEqualTo(data.length);
      ByteBuffer buffer = ByteBuffer.allocate(100);
      channel.position(400_000);
      while (buffer.hasRemaining() && channel.read(buffer) > 0) {}
      assertThat(buffer.array()).isEqualTo(java.util.Arrays.copyOfRange(data, 400_000, 400_100));
    }
  }

  @Test
  void oversizedMessagePublishesNothing() {
    BlobStore store = store(FaultInjector.NONE);
    assertThatThrownBy(() -> store.write(mailbox, new ByteArrayInputStream(message(10_000)), 1_000))
        .isInstanceOf(StorageException.class)
        .extracting(e -> ((StorageException) e).kind())
        .isEqualTo(StorageException.Kind.LIMIT_EXCEEDED);
    assertThat(listAllFiles()).isEmpty();
  }

  @Test
  void diskFailureBeforePublishLeavesNoBlob() throws Exception {
    BlobStore failing =
        store(
            point -> {
              if (point.equals(BlobStore.FAULT_BEFORE_PUBLISH)) {
                throw new IOException("No space left on device");
              }
            });
    assertThatThrownBy(
            () -> failing.write(mailbox, new ByteArrayInputStream(message(100)), 1 << 20))
        .extracting(e -> ((StorageException) e).kind())
        .isEqualTo(StorageException.Kind.UNAVAILABLE);
    assertThat(store(FaultInjector.NONE).list(mailbox)).isEmpty();
    assertThat(listAllFiles()).isEmpty();
  }

  @Test
  void crashBeforePublishLeavesOnlyReclaimableCiphertext() throws Exception {
    BlobStore crashing =
        store(
            point -> {
              if (point.equals(BlobStore.FAULT_BEFORE_PUBLISH)) {
                throw new FaultInjector.SimulatedCrash(point);
              }
            });
    assertThatThrownBy(
            () -> crashing.write(mailbox, new ByteArrayInputStream(message(1000)), 1 << 20))
        .isInstanceOf(FaultInjector.SimulatedCrash.class);
    BlobStore store = store(FaultInjector.NONE);
    assertThat(store.list(mailbox)).isEmpty();
    PlaintextScan.assertNoMarkers(dir, "MARKER");
    store.sweepTemporaryFiles(mailbox);
    assertThat(listAllFiles()).isEmpty();
  }

  @Test
  void tamperedOrTruncatedBlobIsCorruption() throws Exception {
    BlobStore store = store(FaultInjector.NONE);
    byte[] data = message(200_000);
    BlobStore.WrittenBlob blob = store.write(mailbox, new ByteArrayInputStream(data), 1 << 20);
    Path file = store.path(mailbox, blob.blobId());
    byte[] original = Files.readAllBytes(file);
    try (SymmetricKey key = blob.contentKey()) {
      byte[] flipped = original.clone();
      flipped[flipped.length - 100] ^= 1;
      Files.write(file, flipped);
      try (InputStream in = store.open(mailbox, blob.blobId(), key)) {
        assertThatThrownBy(in::readAllBytes).isInstanceOf(BlobStore.BlobCorruptedException.class);
      }
      Files.write(file, java.util.Arrays.copyOf(original, original.length - 70_000));
      try (InputStream in = store.open(mailbox, blob.blobId(), key)) {
        assertThatThrownBy(in::readAllBytes).isInstanceOf(BlobCorruptedException());
      }
      Files.delete(file);
      assertThatThrownBy(() -> store.open(mailbox, blob.blobId(), key))
          .extracting(e -> ((StorageException) e).kind())
          .isEqualTo(StorageException.Kind.CORRUPT);
    }
  }

  @Test
  void blobMovedToAnotherIdFailsAuthentication() throws Exception {
    BlobStore store = store(FaultInjector.NONE);
    BlobStore.WrittenBlob a = store.write(mailbox, new ByteArrayInputStream(message(100)), 1 << 20);
    BlobStore.WrittenBlob b = store.write(mailbox, new ByteArrayInputStream(message(200)), 1 << 20);
    Files.copy(
        store.path(mailbox, a.blobId()),
        store.path(mailbox, b.blobId()),
        java.nio.file.StandardCopyOption.REPLACE_EXISTING);
    try (SymmetricKey key = a.contentKey();
        InputStream in = store.open(mailbox, b.blobId(), key)) {
      assertThatThrownBy(in::readAllBytes).isInstanceOf(IOException.class);
    } finally {
      b.contentKey().close();
    }
  }

  private static Class<BlobStore.BlobCorruptedException> BlobCorruptedException() {
    return BlobStore.BlobCorruptedException.class;
  }

  private java.util.List<Path> listAllFiles() {
    try (var files = Files.walk(dir)) {
      return files.filter(Files::isRegularFile).toList();
    } catch (IOException e) {
      throw new java.io.UncheckedIOException(e);
    }
  }
}
