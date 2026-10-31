package org.shem.search;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.Set;
import org.apache.james.mime4j.utils.search.MessageMatcher;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.shem.common.OpaqueId;
import org.shem.mailbox.MailboxLease;
import org.shem.store.PlaintextScan;
import org.shem.store.SpecialUse;
import org.shem.store.metadata.Folder;
import org.shem.store.metadata.MessageRecord;

class SearchIndexTest {
  private static final String[] WORDS = {
    "alpha",
    "Bravo",
    "charlie",
    "DELTA",
    "echo",
    "foxtrot",
    "Grüße",
    "hôtel",
    "ünïcode",
    "xylophone",
    "zebra",
    "quartz",
    "MARKERWORD",
    "naïve",
    "café",
    "straße"
  };
  @TempDir Path dir;
  private SearchFixture fixture;

  @BeforeEach
  void setUp() throws Exception {
    fixture = new SearchFixture(dir);
  }

  @AfterEach
  void tearDown() {
    fixture.close();
  }

  private static String sentence(Random random, int words) {
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < words; i++) {
      sb.append(WORDS[random.nextInt(WORDS.length)]).append(i % 7 == 6 ? "\r\n" : " ");
    }
    return sb.toString();
  }

  /** Synthetic MIME variety: plain, base64, quoted-printable, Latin-1, multipart. */
  private static byte[] message(Random random, int variant) {
    String subject = sentence(random, 3).trim().replace("\r\n", " ");
    String text = sentence(random, 40);
    String headers =
        "From: bob@example.net\r\nTo: alice@example.org\r\nSubject: "
            + subject
            + "\r\nMIME-Version: 1.0\r\n";
    return switch (variant % 4) {
      case 0 ->
          (headers + "Content-Type: text/plain; charset=utf-8\r\n\r\n" + text)
              .getBytes(StandardCharsets.UTF_8);
      case 1 ->
          (headers
                  + "Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n"
                  + Base64.getMimeEncoder().encodeToString(text.getBytes(StandardCharsets.UTF_8)))
              .getBytes(StandardCharsets.US_ASCII);
      case 2 ->
          (headers + "Content-Type: text/plain; charset=iso-8859-1\r\n\r\n" + text)
              .getBytes(Charset.forName("ISO-8859-1"));
      default ->
          (headers
                  + "Content-Type: multipart/alternative; boundary=XYZ\r\n\r\npreamble "
                  + sentence(random, 3)
                  + "\r\n--XYZ\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n"
                  + text.replace("ü", "=C3=BC").replace("é", "=C3=A9")
                  + "\r\n--XYZ\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>"
                  + sentence(random, 10)
                  + "</p>\r\n--XYZ--\r\nepilogue\r\n")
              .getBytes(StandardCharsets.UTF_8);
    };
  }

  private static boolean exact(byte[] message, String value, boolean headers) throws Exception {
    return MessageMatcher.builder()
        .searchContents(List.of(value))
        .caseInsensitive(true)
        .includeHeaders(headers)
        .build()
        .messageMatches(new ByteArrayInputStream(message));
  }

  @Test
  void candidatesNeverMissAMatchingMessage() throws Exception {
    Random random = new Random(42);
    for (int i = 0; i < 40; i++) {
      fixture.deliver(message(random, i));
    }
    try (MailboxLease lease = fixture.login()) {
      SearchIndex index = lease.extension(SearchIndex.class).orElseThrow();
      assertThat(index.awaitIdle(Duration.ofSeconds(30))).isTrue();
      Map<OpaqueId, byte[]> byBlob = blobs(lease);
      SearchIndex.Snapshot snapshot = index.acquire();
      try {
        assertThat(snapshot.coveredCount()).isEqualTo(40);
        List<String> probes =
            new ArrayList<>(
                List.of("ALPHA", "grüSSe", "ünï", "e c", "xylo", "MARKER", "zzz", "café"));
        for (int i = 0; i < 60; i++) {
          String source = sentence(random, 4);
          int start = random.nextInt(source.length() - 3);
          probes.add(
              source.substring(start, Math.min(source.length(), start + 3 + random.nextInt(8))));
        }
        // Substrings of the raw messages, including ones spanning part and header boundaries.
        List<byte[]> raw = new ArrayList<>(byBlob.values());
        for (int i = 0; i < 150; i++) {
          String m = new String(raw.get(random.nextInt(raw.size())), StandardCharsets.ISO_8859_1);
          int start = random.nextInt(m.length() - 12);
          probes.add(m.substring(start, start + 3 + random.nextInt(9)));
        }
        for (String probe : probes) {
          for (boolean headers : new boolean[] {false, true}) {
            Optional<Set<OpaqueId>> candidates = index.candidates(snapshot, probe, headers);
            assertThat(candidates).isPresent();
            for (Map.Entry<OpaqueId, byte[]> entry : byBlob.entrySet()) {
              if (exact(entry.getValue(), probe, headers)) {
                assertThat(candidates.get())
                    .as("false negative for '%s'", probe)
                    .contains(entry.getKey());
              }
            }
          }
        }
        assertThat(index.candidates(snapshot, "ab", false)).isEmpty();
      } finally {
        index.release(snapshot);
      }
    }
    PlaintextScan.assertNoMarkers(
        dir.resolve("mailboxes"), "MARKERWORD", "XYLOPHONE", "xylophone", "ALP");
  }

  @Test
  void uncoveredMessagesAreReportedUntilIndexed() throws Exception {
    try (MailboxLease lease = fixture.login()) {
      SearchIndex index = lease.extension(SearchIndex.class).orElseThrow();
      fixture.deliver(message(new Random(1), 0));
      assertThat(lease.importPending(10)).isEqualTo(1);
      assertThat(index.awaitIdle(Duration.ofSeconds(30))).isTrue();
      SearchIndex.Snapshot snapshot = index.acquire();
      try {
        for (OpaqueId blob : blobs(lease).keySet()) {
          assertThat(snapshot.covers(blob)).isTrue();
        }
      } finally {
        index.release(snapshot);
      }
    }
  }

  @Test
  void corruptIndexIsRebuiltOnNextUnlock() throws Exception {
    for (int i = 0; i < 5; i++) {
      fixture.deliver(message(new Random(i), i));
    }
    try (MailboxLease lease = fixture.login()) {
      assertThat(lease.extension(SearchIndex.class).orElseThrow().awaitIdle(Duration.ofSeconds(30)))
          .isTrue();
    }
    Path indexDir = fixture.paths.mailbox(fixture.mailboxId).resolve("searchindex");
    try (var files = Files.list(indexDir)) {
      for (Path f : (Iterable<Path>) files::iterator) {
        String name = f.getFileName().toString();
        if (name.startsWith("segments_")) {
          byte[] data = Files.readAllBytes(f);
          data[data.length - 10] ^= 1;
          Files.write(f, data);
        }
      }
    }
    try (MailboxLease lease = fixture.login()) {
      SearchIndex index = lease.extension(SearchIndex.class).orElseThrow();
      assertThat(index.awaitIdle(Duration.ofSeconds(30))).isTrue();
      SearchIndex.Snapshot snapshot = index.acquire();
      try {
        assertThat(snapshot.coveredCount()).isEqualTo(5);
      } finally {
        index.release(snapshot);
      }
    }
  }

  @Test
  void rotationRebuildsTheIndexUnderTheNewDataKey() throws Exception {
    fixture.deliver(message(new Random(7), 0));
    try (MailboxLease lease = fixture.login()) {
      assertThat(lease.extension(SearchIndex.class).orElseThrow().awaitIdle(Duration.ofSeconds(30)))
          .isTrue();
      fixture.lifecycle.rotateKeys(lease, "another strong passphrase");
      SearchIndex rebuilt = lease.extension(SearchIndex.class).orElseThrow();
      assertThat(rebuilt.awaitIdle(Duration.ofSeconds(30))).isTrue();
      SearchIndex.Snapshot snapshot = rebuilt.acquire();
      try {
        assertThat(snapshot.coveredCount()).isEqualTo(1);
      } finally {
        rebuilt.release(snapshot);
      }
    }
    Path marker = fixture.paths.mailbox(fixture.mailboxId).resolve("searchindex/data-version");
    assertThat(Files.readString(marker)).isEqualTo("3");
  }

  private static Map<OpaqueId, byte[]> blobs(MailboxLease lease) throws Exception {
    Map<OpaqueId, byte[]> result = new HashMap<>();
    Folder inbox = lease.read(v -> v.folderByRole(SpecialUse.INBOX).orElseThrow());
    List<MessageRecord> records = new ArrayList<>();
    lease.read(
        v -> {
          v.forEachMessage(inbox.folderId(), (uid, r) -> records.add(r));
          return null;
        });
    for (MessageRecord r : records) {
      try (InputStream in = lease.openMessage(r)) {
        result.put(r.blobId(), in.readAllBytes());
      }
    }
    return result;
  }
}
