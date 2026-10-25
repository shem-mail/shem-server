package org.shem.store;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Scans every file below a directory for known plaintext markers (UTF-8 and UTF-16). A clean scan
 * is evidence, not a cryptographic proof, that no mailbox plaintext was persisted.
 */
public final class PlaintextScan {
  private PlaintextScan() {}

  public static void assertNoMarkers(Path root, String... markers) throws IOException {
    List<String> hits = new ArrayList<>();
    try (var files = Files.walk(root)) {
      for (Path file : (Iterable<Path>) files::iterator) {
        if (!Files.isRegularFile(file)) {
          continue;
        }
        byte[] data = Files.readAllBytes(file);
        for (String marker : markers) {
          if (contains(data, marker.getBytes(StandardCharsets.UTF_8))
              || contains(data, marker.getBytes(StandardCharsets.UTF_16LE))
              || contains(data, marker.getBytes(StandardCharsets.UTF_16BE))) {
            hits.add(root.relativize(file) + " contains marker");
          }
        }
        String name = String.valueOf(file.getFileName());
        for (String marker : markers) {
          if (name.contains(marker)) {
            hits.add(root.relativize(file) + " has marker in name");
          }
        }
      }
    }
    assertThat(hits).as("plaintext markers on disk").isEmpty();
  }

  private static boolean contains(byte[] data, byte[] needle) {
    outer:
    for (int i = 0; i + needle.length <= data.length; i++) {
      for (int j = 0; j < needle.length; j++) {
        if (data[i + j] != needle[j]) {
          continue outer;
        }
      }
      return true;
    }
    return false;
  }
}
