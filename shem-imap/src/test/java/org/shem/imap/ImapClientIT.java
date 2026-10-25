package org.shem.imap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import jakarta.mail.AuthenticationFailedException;
import jakarta.mail.Flags;
import jakarta.mail.Folder;
import jakarta.mail.Message;
import jakarta.mail.Session;
import jakarta.mail.Store;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.search.BodyTerm;
import jakarta.mail.search.FlagTerm;
import jakarta.mail.search.SubjectTerm;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import org.eclipse.angus.mail.imap.IMAPFolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.shem.store.PlaintextScan;
import org.shem.tls.TestCertificates;

/** Interoperability with a real IMAP client implementation (Jakarta Mail / Angus) over TLS. */
class ImapClientIT {
  @TempDir Path dir;
  private ImapFixture fixture;
  private final List<Store> stores = new ArrayList<>();

  @BeforeEach
  void setUp() throws Exception {
    fixture = new ImapFixture(dir);
  }

  @AfterEach
  void tearDown() throws Exception {
    for (Store store : stores) {
      if (store.isConnected()) {
        store.close();
      }
    }
    fixture.close();
  }

  private Store connect(String password) throws Exception {
    SSLContext trust = TestCertificates.clientTrusting(fixture.certificate.certificate());
    Properties props = new Properties();
    props.put("mail.imaps.ssl.socketFactory", trust.getSocketFactory());
    props.put("mail.imaps.ssl.checkserveridentity", "true");
    props.put("mail.imaps.connectiontimeout", "10000");
    props.put("mail.imaps.timeout", "20000");
    Store store = Session.getInstance(props).getStore("imaps");
    stores.add(store);
    store.connect(ImapFixture.HOST, fixture.port, ImapFixture.USER, password);
    return store;
  }

  private static String text(Message message) throws Exception {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    message.writeTo(out);
    return out.toString(StandardCharsets.UTF_8);
  }

  @Test
  void readsMailDeliveredWhileLockedAndSupportsCoreCommands() throws Exception {
    fixture.deliver("First IMAP-MARKER subject", "alpha body IMAP-MARKER");
    fixture.deliver("Second", "beta body");

    Store store = connect(ImapFixture.PASSWORD);
    Folder inbox = store.getFolder("INBOX");
    inbox.open(Folder.READ_WRITE);
    assertThat(inbox.getMessageCount()).isEqualTo(2);
    Message[] messages = inbox.getMessages();
    assertThat(messages[0].getSubject()).isEqualTo("First IMAP-MARKER subject");
    assertThat(((InternetAddress) messages[0].getFrom()[0]).getAddress())
        .isEqualTo("bob@example.net");
    assertThat(text(messages[1])).contains("beta body");
    assertThat(((IMAPFolder) inbox).getUID(messages[0])).isEqualTo(1);
    assertThat(((IMAPFolder) inbox).getUIDValidity()).isPositive();

    // Flags: fetching BODY[] of message 2 above implicitly set \Seen (RFC 3501); message 1 is
    // still unseen until flagged explicitly.
    assertThat(inbox.search(new FlagTerm(new Flags(Flags.Flag.SEEN), false))).hasSize(1);
    messages[0].setFlag(Flags.Flag.SEEN, true);
    messages[0].setFlag(Flags.Flag.FLAGGED, true);
    assertThat(inbox.search(new FlagTerm(new Flags(Flags.Flag.SEEN), false))).isEmpty();
    assertThat(inbox.search(new FlagTerm(new Flags(Flags.Flag.FLAGGED), true))).hasSize(1);

    // SEARCH is complete without an index (exact evaluation)
    assertThat(inbox.search(new SubjectTerm("second"))).hasSize(1);
    assertThat(inbox.search(new BodyTerm("alpha"))).hasSize(1);

    // Folder lifecycle, COPY, EXPUNGE
    Folder archive = store.getFolder("Archive");
    assertThat(archive.create(Folder.HOLDS_MESSAGES)).isTrue();
    inbox.copyMessages(new Message[] {messages[1]}, archive);
    messages[1].setFlag(Flags.Flag.DELETED, true);
    inbox.expunge();
    assertThat(inbox.getMessageCount()).isEqualTo(1);
    archive.open(Folder.READ_ONLY);
    assertThat(archive.getMessageCount()).isEqualTo(1);
    assertThat(text(archive.getMessage(1))).contains("beta body");
    archive.close(false);
    assertThat(archive.renameTo(store.getFolder("Old"))).isTrue();
    assertThat(store.getFolder("Old").exists()).isTrue();

    // APPEND
    MimeMessage draft = new MimeMessage(Session.getInstance(new Properties()));
    draft.setSubject("Appended draft");
    draft.setText("appended body");
    Folder drafts = store.getFolder("Drafts");
    drafts.appendMessages(new Message[] {draft});
    drafts.open(Folder.READ_ONLY);
    assertThat(drafts.getMessage(drafts.getMessageCount()).getSubject())
        .isEqualTo("Appended draft");
    drafts.close(false);

    List<String> names = new ArrayList<>();
    for (Folder f : store.getDefaultFolder().list("*")) {
      names.add(f.getFullName());
    }
    assertThat(names).contains("INBOX", "Sent", "Drafts", "Trash", "Junk", "Old");

    inbox.close(false);
    store.close();
    awaitLocked();
    PlaintextScan.assertNoMarkers(
        dir.resolve("mailboxes"), "IMAP-MARKER", "Archive", "Appended", "bob@example.net");
  }

  @Test
  void idleSessionSeesNewDeliveries() throws Exception {
    Store store = connect(ImapFixture.PASSWORD);
    IMAPFolder inbox = (IMAPFolder) store.getFolder("INBOX");
    inbox.open(Folder.READ_WRITE);
    assertThat(inbox.getMessageCount()).isZero();
    CountDownLatch arrived = new CountDownLatch(1);
    inbox.addMessageCountListener(
        new jakarta.mail.event.MessageCountAdapter() {
          @Override
          public void messagesAdded(jakarta.mail.event.MessageCountEvent e) {
            arrived.countDown();
          }
        });
    Thread idler =
        Thread.ofVirtual()
            .start(
                () -> {
                  try {
                    inbox.idle(true);
                  } catch (Exception ignored) {
                    // folder closed at the end of the test
                  }
                });
    Thread.sleep(300);
    fixture.deliver("Pushed", "arrives during IDLE");
    assertThat(arrived.await(15, TimeUnit.SECONDS)).isTrue();
    idler.join(5000);
    assertThat(inbox.getMessageCount()).isEqualTo(1);
  }

  @Test
  void wrongPasswordIsRejectedAndLogoutLocksTheMailbox() throws Exception {
    assertThatThrownBy(() -> connect("wrong password!"))
        .isInstanceOf(AuthenticationFailedException.class);
    Store store = connect(ImapFixture.PASSWORD);
    assertThat(
            fixture.registry.isUnlocked(
                fixture.identity.loginAccount(ImapFixture.USER).orElseThrow().mailboxId()))
        .isTrue();
    store.close();
    awaitLocked();
  }

  @Test
  void plaintextConnectionsAreNotServed() throws Exception {
    try (java.net.Socket socket =
        new java.net.Socket(java.net.InetAddress.getLoopbackAddress(), fixture.port)) {
      socket.setSoTimeout(3000);
      socket
          .getOutputStream()
          .write("a1 LOGIN alice@example.org secret\r\n".getBytes(StandardCharsets.US_ASCII));
      socket.getOutputStream().flush();
      byte[] buffer = new byte[256];
      int n;
      try {
        n = socket.getInputStream().read(buffer);
      } catch (java.net.SocketTimeoutException | java.net.SocketException e) {
        n = -1;
      }
      String reply = n > 0 ? new String(buffer, 0, n, StandardCharsets.ISO_8859_1) : "";
      assertThat(reply).doesNotContain("OK");
    }
  }

  @Test
  void largeAppendAndFetchNeverTouchTheTempDirectory() throws Exception {
    Path tmp = Path.of(System.getProperty("java.io.tmpdir"));
    java.nio.file.Files.createDirectories(tmp);
    try (java.nio.file.WatchService watcher = tmp.getFileSystem().newWatchService()) {
      // Files created and deleted again still leave plaintext on the medium, so watch creations.
      tmp.register(watcher, java.nio.file.StandardWatchEventKinds.ENTRY_CREATE);
      Store store = connect(ImapFixture.PASSWORD);
      MimeMessage big = new MimeMessage(Session.getInstance(new Properties()));
      big.setSubject("Large TEMPFILE-MARKER");
      big.setText("TEMPFILE-MARKER line of filler text\r\n".repeat(60_000)); // ~2 MiB literal
      Folder inbox = store.getFolder("INBOX");
      inbox.appendMessages(new Message[] {big});
      inbox.open(Folder.READ_ONLY);
      assertThat(text(inbox.getMessage(1))).contains("TEMPFILE-MARKER line");
      inbox.close(false);
      java.nio.file.WatchKey key = watcher.poll(500, TimeUnit.MILLISECONDS);
      List<String> created = new ArrayList<>();
      if (key != null) {
        key.pollEvents().forEach(e -> created.add(String.valueOf(e.context())));
      }
      assertThat(created).as("files created in java.io.tmpdir").isEmpty();
    }
    PlaintextScan.assertNoMarkers(dir.resolve("mailboxes"), "TEMPFILE-MARKER");
  }

  @Test
  void advertisesOnlyTestedCapabilities() throws Exception {
    Store store = connect(ImapFixture.PASSWORD);
    org.eclipse.angus.mail.imap.IMAPStore imap = (org.eclipse.angus.mail.imap.IMAPStore) store;
    for (String supported :
        List.of("IMAP4REV1", "IDLE", "MOVE", "UIDPLUS", "UNSELECT", "NAMESPACE", "SPECIAL-USE")) {
      assertThat(imap.hasCapability(supported)).as(supported).isTrue();
    }
    for (String hidden :
        List.of(
            "CONDSTORE",
            "QRESYNC",
            "ACL",
            "QUOTA",
            "METADATA",
            "COMPRESS=DEFLATE",
            "ESEARCH",
            "LIST-EXTENDED")) {
      assertThat(imap.hasCapability(hidden)).as(hidden).isFalse();
    }
  }

  @Test
  void indexedSearchEqualsExactEvaluationDuringAndAfterIndexing() throws Exception {
    java.util.Random random = new java.util.Random(11);
    String[] words = {
      "apple", "Banana", "cherry", "DATE", "elder", "fig", "grape", "honeydew", "kiwi"
    };
    List<byte[]> raw = new ArrayList<>();
    for (int i = 0; i < 30; i++) {
      StringBuilder body = new StringBuilder();
      for (int w = 0; w < 25; w++) {
        body.append(words[random.nextInt(words.length)]).append(' ');
      }
      byte[] message =
          ("From: bob@example.net\r\nSubject: msg "
                  + i
                  + " "
                  + words[i % words.length]
                  + "\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
                  + body
                  + "\r\n")
              .getBytes(StandardCharsets.UTF_8);
      raw.add(message);
      fixture.deliverRaw(message);
    }
    Store store = connect(ImapFixture.PASSWORD);
    IMAPFolder inbox = (IMAPFolder) store.getFolder("INBOX");
    inbox.open(Folder.READ_ONLY);
    List<String> probes = List.of("banana", "cherry date", "fig grape", "kiwi", "xyz", "elder ");
    for (int round = 0; round < 2; round++) {
      if (round == 1) {
        // The first round may race with background indexing; the second runs once it settled.
        try (org.shem.mailbox.MailboxLease probeLease =
            fixture.sessions.authenticate(
                ImapFixture.USER,
                ImapFixture.PASSWORD,
                java.net.InetAddress.getLoopbackAddress(),
                org.shem.mailbox.Capability.MAIL_ACCESS)) {
          org.shem.search.SearchIndex index =
              probeLease.extension(org.shem.search.SearchIndex.class).orElseThrow();
          assertThat(index.awaitIdle(java.time.Duration.ofSeconds(30))).isTrue();
          org.shem.search.SearchIndex.Snapshot snapshot = index.acquire();
          try {
            assertThat(snapshot.coveredCount()).isEqualTo(30);
          } finally {
            index.release(snapshot);
          }
        }
      }
      for (String probe : probes) {
        java.util.Set<Long> uids = new java.util.TreeSet<>();
        for (Message m : inbox.search(new BodyTerm(probe))) {
          uids.add(inbox.getUID(m));
        }
        java.util.Set<Long> expected = new java.util.TreeSet<>();
        for (int i = 0; i < raw.size(); i++) {
          if (org.apache.james.mime4j.utils.search.MessageMatcher.builder()
              .searchContents(List.of(probe))
              .caseInsensitive(true)
              .includeHeaders(false)
              .build()
              .messageMatches(new java.io.ByteArrayInputStream(raw.get(i)))) {
            expected.add((long) i + 1);
          }
        }
        assertThat(uids).as("round %d probe '%s'", round, probe).isEqualTo(expected);
      }
    }
  }

  private void awaitLocked() throws Exception {
    var mailbox = fixture.identity.loginAccount(ImapFixture.USER).orElseThrow().mailboxId();
    for (int i = 0; i < 100 && fixture.registry.isUnlocked(mailbox); i++) {
      Thread.sleep(50);
    }
    assertThat(fixture.registry.isUnlocked(mailbox)).isFalse();
  }
}
