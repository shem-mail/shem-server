package org.shem.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

class StreamingCipherTest {
  private static final int SEGMENT = 4096;
  private final AssociatedData context =
      AssociatedData.builder(Purpose.MESSAGE_BLOB, 1).id("blob", TestKeys.id()).build();

  private byte[] plaintext(int size) {
    byte[] data = new byte[size];
    TestKeys.RANDOM.nextBytes(data);
    return data;
  }

  private byte[] encrypt(StreamingCipher cipher, byte[] data, AssociatedData aad) throws Exception {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    try (OutputStream encrypting = cipher.encrypt(out, aad)) {
      encrypting.write(data);
    }
    return out.toByteArray();
  }

  private byte[] decrypt(StreamingCipher cipher, byte[] ciphertext, AssociatedData aad)
      throws Exception {
    try (InputStream in = cipher.decrypt(new ByteArrayInputStream(ciphertext), aad)) {
      return in.readAllBytes();
    }
  }

  @Test
  void roundTripsAcrossSegmentBoundaries() throws Exception {
    try (SymmetricKey key = SymmetricKey.generate(TestKeys.RANDOM)) {
      StreamingCipher cipher = key.streaming(SEGMENT);
      for (int size : new int[] {0, 1, SEGMENT - 40, SEGMENT, 3 * SEGMENT + 17}) {
        byte[] data = plaintext(size);
        assertThat(decrypt(cipher, encrypt(cipher, data, context), context)).isEqualTo(data);
      }
    }
  }

  @Test
  void detectsTruncationAtEverySegmentBoundary() throws Exception {
    try (SymmetricKey key = SymmetricKey.generate(TestKeys.RANDOM)) {
      StreamingCipher cipher = key.streaming(SEGMENT);
      byte[] ciphertext = encrypt(cipher, plaintext(5 * SEGMENT), context);
      for (int cut = SEGMENT; cut < ciphertext.length; cut += SEGMENT) {
        byte[] truncated = Arrays.copyOf(ciphertext, cut);
        assertThatThrownBy(() -> decrypt(cipher, truncated, context))
            .isInstanceOf(IOException.class);
      }
    }
  }

  @Test
  void detectsReorderedSegmentsAndBitFlips() throws Exception {
    try (SymmetricKey key = SymmetricKey.generate(TestKeys.RANDOM)) {
      StreamingCipher cipher = key.streaming(SEGMENT);
      byte[] ciphertext = encrypt(cipher, plaintext(4 * SEGMENT), context);
      byte[] reordered = ciphertext.clone();
      // Swap the second and third full ciphertext segments (header lives in the first).
      System.arraycopy(ciphertext, 2 * SEGMENT, reordered, SEGMENT, SEGMENT);
      System.arraycopy(ciphertext, SEGMENT, reordered, 2 * SEGMENT, SEGMENT);
      assertThatThrownBy(() -> decrypt(cipher, reordered, context)).isInstanceOf(IOException.class);

      byte[] flipped = ciphertext.clone();
      flipped[flipped.length / 2] ^= 0x40;
      assertThatThrownBy(() -> decrypt(cipher, flipped, context)).isInstanceOf(IOException.class);
    }
  }

  @Test
  void rejectsCrossFileSubstitution() throws Exception {
    try (SymmetricKey key = SymmetricKey.generate(TestKeys.RANDOM)) {
      StreamingCipher cipher = key.streaming(SEGMENT);
      byte[] ciphertext = encrypt(cipher, plaintext(100), context);
      AssociatedData otherBlob =
          AssociatedData.builder(Purpose.MESSAGE_BLOB, 1).id("blob", TestKeys.id()).build();
      assertThatThrownBy(() -> decrypt(cipher, ciphertext, otherBlob))
          .isInstanceOf(IOException.class);
    }
  }

  @Test
  void seekableDecryptionReadsRandomRanges() throws Exception {
    try (SymmetricKey key = SymmetricKey.generate(TestKeys.RANDOM)) {
      StreamingCipher cipher = key.streaming(SEGMENT);
      byte[] data = plaintext(10 * SEGMENT + 123);
      byte[] ciphertext = encrypt(cipher, data, context);
      try (SeekableByteChannel channel =
          cipher.decryptSeekable(new InMemoryChannel(ciphertext), context)) {
        assertThat(channel.size()).isEqualTo(data.length);
        for (long position : new long[] {0, 5000, 4096 * 7 - 3, data.length - 10}) {
          ByteBuffer buffer = ByteBuffer.allocate(10);
          channel.position(position);
          while (buffer.hasRemaining() && channel.read(buffer) > 0) {}
          assertThat(buffer.array())
              .isEqualTo(Arrays.copyOfRange(data, (int) position, (int) position + 10));
        }
      }
    }
  }

  /** Minimal read-only in-memory seekable channel. */
  static final class InMemoryChannel implements SeekableByteChannel {
    private final byte[] data;
    private long position;
    private boolean open = true;

    InMemoryChannel(byte[] data) {
      this.data = data;
    }

    @Override
    public int read(ByteBuffer dst) {
      if (position >= data.length) {
        return -1;
      }
      int n = (int) Math.min(dst.remaining(), data.length - position);
      dst.put(data, (int) position, n);
      position += n;
      return n;
    }

    @Override
    public int write(ByteBuffer src) {
      throw new UnsupportedOperationException();
    }

    @Override
    public long position() {
      return position;
    }

    @Override
    public SeekableByteChannel position(long newPosition) {
      position = newPosition;
      return this;
    }

    @Override
    public long size() {
      return data.length;
    }

    @Override
    public SeekableByteChannel truncate(long size) {
      throw new UnsupportedOperationException();
    }

    @Override
    public boolean isOpen() {
      return open;
    }

    @Override
    public void close() {
      open = false;
    }
  }
}
