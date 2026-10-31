package org.shem.mailbox;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.shem.common.FaultInjector;
import org.shem.crypto.Secret;
import org.shem.identity.EmailAddress;
import org.shem.store.SpecialUse;
import org.shem.store.metadata.Flags;
import org.shem.store.metadata.Folder;

class MailboxExportTest {
  private static final String PASSWORD = "correct horse battery staple";
  private static final InetAddress CLIENT = InetAddress.getLoopbackAddress();
  private static final long DATE = Instant.parse("2026-10-25T08:05:09Z").toEpochMilli();
  @TempDir Path dir;
  private TestMailServer server;

  @BeforeEach
  void setUp() throws Exception {
    server = new TestMailServer(dir, Clock.systemUTC(), FaultInjector.NONE, Duration.ZERO);
    server.identity.createDomain("example.org");
    MailboxProvisioning.Provisioned provisioned =
        server.provisioning.provision(
            EmailAddress.parse("alice@example.org"), 0, Duration.ofDays(1));
    String bootstrap;
    try (Secret secret = provisioned.bootstrapPassword()) {
      bootstrap = new String(secret.exposeCopy(), StandardCharsets.UTF_8);
    }
    try (MailboxLease enrollment =
        server.sessions.authenticate("alice@example.org", bootstrap, CLIENT, Capability.ENROLL)) {
      server.lifecycle.enroll(enrollment, PASSWORD);
    }
  }

  @AfterEach
  void tearDown() {
    server.close();
  }

  private MailboxLease unlock() throws Exception {
    return server.sessions.authenticate(
        "alice@example.org", PASSWORD, CLIENT, Capability.MAIL_ACCESS);
  }

  private static Map<String, String> unzip(byte[] zip) throws IOException {
    Map<String, String> entries = new LinkedHashMap<>();
    try (ZipInputStream in = new ZipInputStream(new ByteArrayInputStream(zip))) {
      ZipEntry entry;
      while ((entry = in.getNextEntry()) != null) {
        entries.put(entry.getName(), new String(in.readAllBytes(), StandardCharsets.UTF_8));
      }
    }
    return entries;
  }

  @Test
  @SuppressWarnings("StringConcatToTextBlock")
  void exportsEveryFolderAsMboxrdWithAManifest() throws Exception {
    byte[] tricky =
        ("Subject: quoting\r\n\r\nFrom the start\r\n>From quoted\r\nnot From here\r\n>>From two\r\n"
                + "From")
            .getBytes(StandardCharsets.UTF_8);
    try (MailboxLease lease = unlock()) {
      Folder inbox = lease.read(v -> v.folderByRole(SpecialUse.INBOX).orElseThrow());
      Folder work = lease.write(tx -> tx.createFolder("Work \"q\"/Ünï", SpecialUse.NONE));
      lease.append(
          inbox.folderId(),
          new ByteArrayInputStream("Subject: one\r\n\r\nbody\r\n".getBytes(StandardCharsets.UTF_8)),
          new Flags(Flags.SEEN | Flags.FLAGGED, List.of("$Label1")),
          DATE);
      lease.append(work.folderId(), new ByteArrayInputStream(tricky), Flags.NONE, DATE);

      ByteArrayOutputStream out = new ByteArrayOutputStream();
      MailboxExport.Summary summary = MailboxExport.write(lease, out, Instant.EPOCH);
      assertThat(summary.messages()).isEqualTo(2);

      Map<String, String> entries = unzip(out.toByteArray());
      assertThat(entries.keySet()).last().isEqualTo("manifest.json");
      String manifest = entries.get("manifest.json");
      assertThat(manifest)
          .contains("\"format\":\"" + MailboxExport.FORMAT + "\"")
          .contains("\"name\":\"Work \\\"q\\\"/Ünï\"")
          .contains("\"flags\":[\"\\\\Seen\",\"\\\\Flagged\"],\"keywords\":[\"$Label1\"]")
          .contains("\"internalDate\":\"2026-10-25T08:05:09Z\"");
      assertThat(entries.keySet())
          .allMatch(n -> n.equals("manifest.json") || n.matches("folders/\\d+\\.mbox"));

      String inboxMbox =
          entries.values().stream()
              .filter(v -> v.contains("Subject: one"))
              .findFirst()
              .orElseThrow();
      assertThat(inboxMbox)
          .isEqualTo("From MAILER-DAEMON Sun Oct 25 08:05:09 2026\nSubject: one\r\n\r\nbody\r\n\n");
      String workMbox =
          entries.values().stream().filter(v -> v.contains("quoting")).findFirst().orElseThrow();
      assertThat(workMbox)
          .isEqualTo(
              "From MAILER-DAEMON Sun Oct 25 08:05:09 2026\n"
                  + "Subject: quoting\r\n\r\n>From the start\r\n>>From quoted\r\nnot From here\r\n"
                  + ">>>From two\r\nFrom\n\n");
    }
  }

  @Test
  void quotingIsIndependentOfBufferBoundaries() throws Exception {
    byte[] input =
        "From a\n>From b\n>>x\nFro\nFrom\n\n>\nFromage\n".getBytes(StandardCharsets.US_ASCII);
    ByteArrayOutputStream whole = new ByteArrayOutputStream();
    MailboxExport.MboxrdQuoter quoter = new MailboxExport.MboxrdQuoter(whole);
    quoter.write(input, input.length);
    quoter.finish();
    assertThat(whole.toString(StandardCharsets.US_ASCII))
        .isEqualTo(">From a\n>>From b\n>>x\nFro\nFrom\n\n>\nFromage\n");

    ByteArrayOutputStream bytewise = new ByteArrayOutputStream();
    MailboxExport.MboxrdQuoter slow = new MailboxExport.MboxrdQuoter(bytewise);
    for (byte b : input) {
      slow.write(new byte[] {b}, 1);
    }
    slow.finish();
    assertThat(bytewise.toByteArray()).isEqualTo(whole.toByteArray());
  }

  @Test
  void aRevokedLeaseStopsTheExport() throws Exception {
    MailboxLease lease = unlock();
    Folder inbox = lease.read(v -> v.folderByRole(SpecialUse.INBOX).orElseThrow());
    for (int i = 0; i < 3; i++) {
      lease.append(
          inbox.folderId(),
          new ByteArrayInputStream(
              ("Subject: " + i + "\r\n\r\nx\r\n").getBytes(StandardCharsets.UTF_8)),
          Flags.NONE,
          DATE);
    }
    OutputStream revokeOnFirstWrite =
        new OutputStream() {
          @Override
          public void write(int b) {
            server.registry.revokeMailbox(lease.mailboxId());
          }

          @Override
          public void write(byte[] b, int off, int len) {
            server.registry.revokeMailbox(lease.mailboxId());
          }
        };
    assertThatThrownBy(() -> MailboxExport.write(lease, revokeOnFirstWrite, Instant.EPOCH))
        .isInstanceOf(RevokedLeaseException.class);
    lease.close();
  }
}
