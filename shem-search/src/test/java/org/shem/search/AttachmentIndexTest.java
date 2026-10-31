package org.shem.search;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.shem.common.OpaqueId;
import org.shem.mailbox.MailboxLease;
import org.shem.store.SpecialUse;
import org.shem.store.metadata.Folder;

class AttachmentIndexTest {
  @TempDir Path dir;
  private SearchFixture fixture;
  private final FakeExtractor extractor = new FakeExtractor();

  /** Behaves by declared content type; records what it was asked to extract. */
  static final class FakeExtractor implements AttachmentExtractor {
    final List<String> seen = new ArrayList<>();
    volatile boolean available = true;

    @Override
    public Outcome extract(InputStream content, @Nullable String type, @Nullable String extension)
        throws UnavailableException, IOException {
      if (!available) {
        throw new UnavailableException("no worker");
      }
      seen.add(type + "/" + extension);
      String text = new String(content.readAllBytes(), StandardCharsets.UTF_8);
      return switch (String.valueOf(type)) {
        case "application/x-locked" -> new Outcome.Encrypted();
        case "application/x-long" -> new Outcome.Text(text, true);
        case "application/x-binary" -> new Outcome.Unsupported();
        default -> new Outcome.Text(text, false);
      };
    }
  }

  @BeforeEach
  void setUp() throws Exception {
    fixture = new SearchFixture(dir, List.of(new AttachmentIndexFactory(extractor)));
  }

  @AfterEach
  void tearDown() {
    fixture.close();
  }

  private static byte[] withAttachment(String type, String fileName, String content) {
    return ("From: bob@example.net\r\nTo: alice@example.org\r\nSubject: s\r\nMIME-Version: 1.0\r\n"
            + "Content-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\n"
            + "Content-Type: text/plain\r\n\r\nbody text only\r\n--B\r\n"
            + "Content-Type: "
            + type
            + "\r\nContent-Disposition: attachment; filename=\""
            + fileName
            + "\"\r\nContent-Transfer-Encoding: base64\r\n\r\n"
            + Base64.getMimeEncoder().encodeToString(content.getBytes(StandardCharsets.UTF_8))
            + "\r\n--B--\r\n")
        .getBytes(StandardCharsets.US_ASCII);
  }

  private static byte[] plain(String body) {
    return ("From: bob@example.net\r\nSubject: p\r\n\r\n" + body + "\r\n")
        .getBytes(StandardCharsets.US_ASCII);
  }

  private record View(AttachmentIndex index, List<OpaqueId> blobs) {}

  private View view(MailboxLease lease) throws Exception {
    AttachmentIndex index = lease.extension(AttachmentIndex.class).orElseThrow();
    assertThat(index.awaitIdle(Duration.ofSeconds(30))).isTrue();
    Folder inbox = lease.read(v -> v.folderByRole(SpecialUse.INBOX).orElseThrow());
    List<OpaqueId> blobs = new ArrayList<>();
    lease.read(
        v -> {
          v.forEachMessage(
              inbox.folderId(),
              (uid, record) -> {
                blobs.add(record.blobId());
                return true;
              });
          return null;
        });
    return new View(index, blobs);
  }

  @Test
  void attachmentTextIsSearchableWithExplicitCoverage() throws Exception {
    fixture.deliver(plain("no attachments"));
    fixture.deliver(withAttachment("application/pdf", "Report.PDF", "Quarterly\r\nREPORT figures"));
    fixture.deliver(withAttachment("application/x-locked", "secret.pdf", "hidden words"));
    fixture.deliver(withAttachment("image/png", "photo.png", "not text"));
    fixture.deliver(withAttachment("application/x-long", "long.txt", "truncated content"));
    try (MailboxLease lease = fixture.login()) {
      View view = view(lease);
      AttachmentIndex.Snapshot snapshot = view.index().acquire();
      try {
        for (OpaqueId blob : view.blobs()) {
          assertThat(snapshot.covers(blob)).as("every message covered").isTrue();
        }
        assertThat(snapshot.incomplete(view.blobs().get(0))).as("no attachments").isFalse();
        assertThat(snapshot.incomplete(view.blobs().get(1))).isFalse();
        assertThat(snapshot.incomplete(view.blobs().get(2))).as("encrypted").isTrue();
        assertThat(snapshot.incomplete(view.blobs().get(3)))
            .as("images are out of scope")
            .isFalse();
        assertThat(snapshot.incomplete(view.blobs().get(4))).as("truncated").isTrue();

        assertThat(view.index().matches(snapshot, "quarterly report"))
            .contains(Set.of(view.blobs().get(1)));
        assertThat(view.index().matches(snapshot, "body text"))
            .as("message bodies are not attachment text")
            .contains(Set.of());
        assertThat(view.index().matches(snapshot, "hidden")).contains(Set.of());
        assertThat(view.index().matches(snapshot, "ab")).isEmpty();
      } finally {
        view.index().release(snapshot);
      }
    }
    assertThat(extractor.seen)
        .as("images never reach a worker; only the extension is passed as a hint")
        .containsExactly(
            "application/pdf/pdf", "application/x-locked/pdf", "application/x-long/txt");
    org.shem.store.PlaintextScan.assertNoMarkers(dir, "Quarterly", "QUARTERLY", "figures");
  }

  @Test
  void anUnavailableExtractorLeavesMessagesPendingUntilRetried() throws Exception {
    extractor.available = false;
    fixture.deliver(withAttachment("application/pdf", "a.pdf", "pending words"));
    try (MailboxLease lease = fixture.login()) {
      View view = view(lease);
      AttachmentIndex.Snapshot before = view.index().acquire();
      try {
        assertThat(before.covers(view.blobs().get(0)))
            .as("never covered without extraction")
            .isFalse();
      } finally {
        view.index().release(before);
      }
      extractor.available = true;
      view.index().retry();
      assertThat(view.index().awaitIdle(Duration.ofSeconds(30))).isTrue();
      AttachmentIndex.Snapshot after = view.index().acquire();
      try {
        assertThat(after.covers(view.blobs().get(0))).isTrue();
        assertThat(view.index().matches(after, "pending words"))
            .contains(Set.of(view.blobs().get(0)));
      } finally {
        view.index().release(after);
      }
    }
  }

  @Test
  void coverageSurvivesRelockWithoutReextraction() throws Exception {
    fixture.deliver(withAttachment("application/pdf", "a.pdf", "persisted text"));
    try (MailboxLease lease = fixture.login()) {
      view(lease);
    }
    fixture.registry.revokeMailbox(fixture.mailboxId);
    int calls = extractor.seen.size();
    try (MailboxLease lease = fixture.login()) {
      View view = view(lease);
      AttachmentIndex.Snapshot snapshot = view.index().acquire();
      try {
        assertThat(view.index().matches(snapshot, "persisted"))
            .contains(Set.of(view.blobs().get(0)));
      } finally {
        view.index().release(snapshot);
      }
    }
    assertThat(extractor.seen).hasSize(calls);
  }
}
