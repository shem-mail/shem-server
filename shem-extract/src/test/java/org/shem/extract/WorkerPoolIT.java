package org.shem.extract;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.encryption.AccessPermission;
import org.apache.pdfbox.pdmodel.encryption.StandardProtectionPolicy;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.shem.search.AttachmentExtractor.Outcome;

/** Real worker processes running Tika (ADR 0019). Synthetic documents only. */
class WorkerPoolIT {
  @TempDir Path dir;
  private WorkerPool pool;

  @AfterEach
  void tearDown() {
    if (pool != null) {
      pool.close();
    }
  }

  private ExtractionSettings settings(List<String> sandbox, Path scratch, boolean require) {
    return new ExtractionSettings(
        sandbox,
        scratch,
        dir.resolve("data/.extraction-canary"),
        2,
        Duration.ofSeconds(30),
        8 << 20,
        4096,
        256,
        50,
        require);
  }

  private WorkerPool unisolated() throws Exception {
    Files.createDirectories(dir.resolve("scratch/w99-left-by-a-crash"));
    pool = new WorkerPool(settings(List.of(), dir.resolve("scratch"), false));
    pool.start();
    return pool;
  }

  private static Outcome extract(WorkerPool pool, byte[] content, String type, String ext)
      throws Exception {
    return pool.extract(new ByteArrayInputStream(content), type, ext);
  }

  private static String text(Outcome outcome) {
    assertThat(outcome).as(outcome.toString()).isInstanceOf(Outcome.Text.class);
    return ((Outcome.Text) outcome).text();
  }

  private static byte[] pdf(String text, boolean encrypted) throws Exception {
    try (PDDocument document = new PDDocument()) {
      PDPage page = new PDPage();
      document.addPage(page);
      try (PDPageContentStream content = new PDPageContentStream(document, page)) {
        content.beginText();
        content.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA), 12);
        content.newLineAtOffset(72, 700);
        content.showText(text);
        content.endText();
      }
      if (encrypted) {
        StandardProtectionPolicy policy =
            new StandardProtectionPolicy("owner-secret", "user-secret", new AccessPermission());
        policy.setEncryptionKeyLength(128);
        document.protect(policy);
      }
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      document.save(out);
      return out.toByteArray();
    }
  }

  /** A minimal WordprocessingML package, built by hand (no OOXML schema jars needed). */
  private static byte[] docx(String text) throws Exception {
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    try (ZipOutputStream zip = new ZipOutputStream(bytes)) {
      entry(
          zip,
          "[Content_Types].xml",
          "<?xml version=\"1.0\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">"
              + "<Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>"
              + "<Default Extension=\"xml\" ContentType=\"application/xml\"/>"
              + "<Override PartName=\"/word/document.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/></Types>");
      entry(
          zip,
          "_rels/.rels",
          "<?xml version=\"1.0\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">"
              + "<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"word/document.xml\"/></Relationships>");
      entry(
          zip,
          "word/document.xml",
          "<?xml version=\"1.0\"?><w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">"
              + "<w:body><w:p><w:r><w:t>"
              + text
              + "</w:t></w:r></w:p></w:body></w:document>");
    }
    return bytes.toByteArray();
  }

  private static void entry(ZipOutputStream zip, String name, String content) throws Exception {
    zip.putNextEntry(new ZipEntry(name));
    zip.write(content.getBytes(StandardCharsets.UTF_8));
    zip.closeEntry();
  }

  @Test
  void extractsTheSupportedFormats() throws Exception {
    WorkerPool pool = unisolated();
    assertThat(dir.resolve("scratch/w99-left-by-a-crash")).as("stale scratch wiped").doesNotExist();
    assertThat(
            text(
                extract(
                    pool,
                    "plain MARKER-TXT".getBytes(StandardCharsets.UTF_8),
                    "text/plain",
                    "txt")))
        .contains("MARKER-TXT");
    assertThat(
            text(
                extract(
                    pool,
                    "<html><body><p>MARKER-HTML</p></body></html>".getBytes(StandardCharsets.UTF_8),
                    "text/html",
                    "html")))
        .contains("MARKER-HTML");
    assertThat(
            text(
                extract(
                    pool,
                    "a,b\nMARKER-CSV,2\n".getBytes(StandardCharsets.UTF_8),
                    "text/csv",
                    "csv")))
        .contains("MARKER-CSV");
    assertThat(
            text(
                extract(
                    pool,
                    "{\\rtf1\\ansi\\deff0{\\fonttbl{\\f0 Times;}}\\f0\\pard MARKER-RTF\\par}"
                        .getBytes(StandardCharsets.US_ASCII),
                    "application/rtf",
                    "rtf")))
        .contains("MARKER-RTF");
    assertThat(text(extract(pool, pdf("MARKER-PDF", false), "application/pdf", "pdf")))
        .contains("MARKER-PDF");
    assertThat(
            text(
                extract(
                    pool,
                    docx("MARKER-DOCX"),
                    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    "docx")))
        .contains("MARKER-DOCX");
    byte[] eml =
        "From: a@example.net\r\nSubject: inner\r\nContent-Type: text/plain\r\n\r\nMARKER-EML\r\n"
            .getBytes(StandardCharsets.US_ASCII);
    assertThat(text(extract(pool, eml, "message/rfc822", "eml"))).contains("MARKER-EML");
  }

  @Test
  void reportsEncryptedUnsupportedTruncatedAndBombs() throws Exception {
    WorkerPool pool = unisolated();
    assertThat(extract(pool, pdf("SECRET", true), "application/pdf", "pdf"))
        .isInstanceOf(Outcome.Encrypted.class);
    byte[] png = {(byte) 0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n', 0, 0, 0, 0};
    assertThat(extract(pool, png, "image/png", "png")).isInstanceOf(Outcome.Unsupported.class);
    Outcome big =
        extract(
            pool, "word ".repeat(10_000).getBytes(StandardCharsets.US_ASCII), "text/plain", null);
    assertThat(big).isInstanceOf(Outcome.Text.class);
    assertThat(((Outcome.Text) big).truncated()).isTrue();
    assertThat(((Outcome.Text) big).text().length()).isLessThanOrEqualTo(4096);

    // A DOCX whose document part inflates more than a thousandfold.
    ByteArrayOutputStream bomb = new ByteArrayOutputStream();
    try (ZipOutputStream zip = new ZipOutputStream(bomb)) {
      zip.putNextEntry(new ZipEntry("[Content_Types].xml"));
      zip.write(
          ("<?xml version=\"1.0\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">"
                  + "<Override PartName=\"/word/document.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/></Types>")
              .getBytes(StandardCharsets.UTF_8));
      zip.putNextEntry(new ZipEntry("word/document.xml"));
      byte[] zeros = new byte[1 << 20];
      for (int i = 0; i < 64; i++) {
        zip.write(zeros);
      }
    }
    Outcome outcome =
        extract(
            pool,
            bomb.toByteArray(),
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "docx");
    assertThat(outcome).isNotInstanceOf(Outcome.Text.class);

    assertThat(pool.extract(new ByteArrayInputStream(new byte[(8 << 20) + 1]), "text/plain", null))
        .isEqualTo(new Outcome.LimitReached("input size"));
  }

  @Test
  void aStuckWorkerIsKilledAtTheTimeoutAndItsScratchRemoved() throws Exception {
    Path scratch = dir.resolve("scratch");
    pool =
        new WorkerPool(
            new ExtractionSettings(
                List.of(),
                scratch,
                dir.resolve("data/.extraction-canary"),
                1,
                Duration.ofSeconds(2),
                1 << 20,
                4096,
                128,
                10,
                false),
            HangingWorker.class.getName());
    pool.start();
    long started = System.nanoTime();
    assertThat(extract(pool, "x".getBytes(StandardCharsets.US_ASCII), "text/plain", null))
        .isEqualTo(new Outcome.LimitReached("time"));
    assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofSeconds(20));
    try (Stream<Path> left = Files.list(scratch)) {
      assertThat(left.toList()).as("killed worker's scratch deleted").isEmpty();
    }
  }

  @Test
  void requiredIsolationRefusesAnUnsandboxedWorker() throws Exception {
    pool = new WorkerPool(settings(List.of(), dir.resolve("scratch"), true));
    assertThatThrownBy(pool::start)
        .isInstanceOf(WorkerPool.IsolationException.class)
        .hasMessageContaining("network reachable")
        .hasMessageContaining("scratch is not a private tmpfs");
  }

  @Test
  void theReferenceSandboxPassesTheIsolationProbe() throws Exception {
    assumeTrue("root".equals(System.getProperty("user.name")), "needs root for namespaces");
    assumeTrue(Files.isDirectory(Path.of("/dev/shm")), "needs a tmpfs at /dev/shm");
    Path data = dir.resolve("data");
    Files.createDirectories(data);
    Path scratch = Files.createTempDirectory(Path.of("/dev/shm"), "shem-extract-test");
    try {
      List<String> sandbox =
          List.of(
              "unshare",
              "--net",
              "--mount",
              "--propagation",
              "private",
              "sh",
              "-c",
              "mount -t tmpfs -o size=1m tmpfs \"$0\" && exec \"$@\"",
              data.toString());
      pool = new WorkerPool(settings(sandbox, scratch, true));
      WorkerPool.Isolation isolation = pool.start();
      assertThat(isolation.networkReachable()).isFalse();
      assertThat(isolation.canaryReadable()).isFalse();
      assertThat(isolation.tmpfsScratch()).isTrue();
      assertThat(text(extract(pool, pdf("SANDBOXED", false), "application/pdf", "pdf")))
          .contains("SANDBOXED");
    } finally {
      pool.close();
      pool = null;
      WorkerPool.deleteTree(scratch);
    }
  }
}
