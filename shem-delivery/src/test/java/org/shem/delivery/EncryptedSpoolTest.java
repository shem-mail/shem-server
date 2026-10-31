package org.shem.delivery;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class EncryptedSpoolTest {
  private static final SecureRandom RANDOM = new SecureRandom();
  @TempDir Path dir;

  private static byte[] message() {
    return "Subject: SPOOL-MARKER\r\n\r\nSPOOL-MARKER body\r\n"
        .repeat(5000)
        .getBytes(StandardCharsets.US_ASCII);
  }

  @Test
  void streamedSpoolRoundTripsAndHoldsOnlyCiphertext() throws Exception {
    byte[] message = message();
    try (EncryptedSpool spool = EncryptedSpool.create(dir, RANDOM)) {
      try (OutputStream out = spool.output(1 << 20)) {
        out.write(message, 0, 1000);
        out.write(message, 1000, message.length - 1000);
      }
      assertThat(spool.size()).isEqualTo(message.length);
      try (InputStream in = spool.open()) {
        assertThat(in.readAllBytes()).isEqualTo(message);
      }
      try (Stream<Path> files = Files.list(dir)) {
        for (Path file : files.toList()) {
          assertThat(new String(Files.readAllBytes(file), StandardCharsets.ISO_8859_1))
              .doesNotContain("SPOOL-MARKER");
        }
      }
    }
    try (Stream<Path> files = Files.list(dir)) {
      assertThat(files.count()).as("closed spool deleted").isZero();
    }
  }

  @Test
  void exceedingTheLimitFailsAndLeavesTheSpoolUnsealed() throws Exception {
    try (EncryptedSpool spool = EncryptedSpool.create(dir, RANDOM)) {
      OutputStream out = spool.output(100);
      out.write(new byte[100]);
      assertThatThrownBy(() -> out.write(1))
          .isInstanceOf(EncryptedSpool.SpoolLimitIOException.class);
      out.close();
      assertThatThrownBy(spool::open).isInstanceOf(IllegalStateException.class);
    }
  }
}
