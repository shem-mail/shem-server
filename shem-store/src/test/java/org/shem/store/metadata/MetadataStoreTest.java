package org.shem.store.metadata;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.shem.common.FaultInjector;
import org.shem.common.IdGenerator;
import org.shem.common.ImmutableBytes;
import org.shem.common.OpaqueId;
import org.shem.crypto.SymmetricKey;
import org.shem.store.PlaintextScan;
import org.shem.store.SpecialUse;
import org.shem.store.StorageException;

class MetadataStoreTest {
  private static final SecureRandom RANDOM = new SecureRandom();
  @TempDir Path dir;
  private final OpaqueId mailbox = OpaqueId.random(RANDOM);
  private SymmetricKey root;
  private final AtomicReference<String> crashAt = new AtomicReference<>("");
  private final List<MetadataStore> open = new ArrayList<>();

  @BeforeEach
  void setUp() {
    root = SymmetricKey.generate(RANDOM);
  }

  @AfterEach
  void tearDown() throws Exception {
    for (MetadataStore store : open) {
      store.close();
    }
    root.close();
  }

  private MetadataStore.Environment env(MetadataStore.Options options) {
    FaultInjector faults =
        point -> {
          if (point.equals(crashAt.get())) {
            throw new FaultInjector.SimulatedCrash(point);
          }
        };
    return new MetadataStore.Environment(
        IdGenerator.secure(RANDOM), RANDOM, Clock.systemUTC(), faults, options);
  }

  private MetadataStore create() throws Exception {
    MetadataStore store =
        MetadataStore.create(dir, mailbox, root, 1, env(MetadataStore.Options.DEFAULT));
    open.add(store);
    return store;
  }

  private MetadataStore reopen(
      @org.jspecify.annotations.Nullable MetadataStore previous, MetadataStore.Options options)
      throws Exception {
    if (previous != null) {
      previous.close();
      open.remove(previous);
    }
    MetadataStore store =
        MetadataStore.open(
            dir, mailbox, v -> v == 1 ? Optional.of(root) : Optional.empty(), env(options));
    open.add(store);
    return store;
  }

  private static NewMessage message(String keyword) {
    return new NewMessage(
        OpaqueId.random(RANDOM),
        ImmutableBytes.copyOf(new byte[] {1, 2, 3}),
        1000,
        1_700_000_000_000L,
        new Flags(0, List.of(keyword)),
        ImmutableBytes.copyOf("MARKER-ENVELOPE Subject".getBytes(StandardCharsets.UTF_8)));
  }

  @Test
  void foldersMessagesFlagsCopyAndExpungeSurviveRestart() throws Exception {
    MetadataStore store = create();
    Folder inbox = store.write(tx -> tx.createFolder("INBOX", SpecialUse.INBOX));
    Folder archive =
        store.write(tx -> tx.createFolder("Archive/MARKER-FOLDER", SpecialUse.ARCHIVE));
    long uid1 = store.write(tx -> tx.append(inbox.folderId(), message("MarkerKeyword")));
    long uid2 = store.write(tx -> tx.append(inbox.folderId(), message("other")));
    store.write(
        tx ->
            tx.setFlags(new MessageKey(inbox.folderId(), uid1), new Flags(Flags.SEEN, List.of())));
    long copied =
        store.write(tx -> tx.copy(new MessageKey(inbox.folderId(), uid2), archive.folderId()));
    store.write(
        tx -> {
          tx.remove(new MessageKey(inbox.folderId(), uid2));
          tx.setSubscribed("Archive/MARKER-FOLDER", true);
          return null;
        });

    MetadataStore reopened = reopen(store, MetadataStore.Options.DEFAULT);
    reopened.read(
        view -> {
          assertThat(view.folderByRole(SpecialUse.INBOX)).isPresent();
          assertThat(view.uids(inbox.folderId())).containsExactly(uid1);
          assertThat(view.uids(archive.folderId())).containsExactly(copied);
          assertThat(
                  view.message(new MessageKey(inbox.folderId(), uid1))
                      .orElseThrow()
                      .flags()
                      .has(Flags.SEEN))
              .isTrue();
          assertThat(view.folder(inbox.folderId()).orElseThrow().uidNext()).isEqualTo(uid2 + 1);
          assertThat(view.subscriptions()).containsExactly("Archive/MARKER-FOLDER");
          MessageRecord copy =
              view.message(new MessageKey(archive.folderId(), copied)).orElseThrow();
          assertThat(copy.modSeq()).isLessThanOrEqualTo(view.highestModSeq());
          return null;
        });
    PlaintextScan.assertNoMarkers(dir, "MARKER", "INBOX", "Archive", "MarkerKeyword", "Subject");
  }

  @Test
  void uidsAreNeverReusedAfterExpungeCompactionAndRestart() throws Exception {
    MetadataStore store = create();
    Folder inbox = store.write(tx -> tx.createFolder("INBOX", SpecialUse.INBOX));
    long last = 0;
    for (int i = 0; i < 5; i++) {
      last = store.write(tx -> tx.append(inbox.folderId(), message("k")));
    }
    long lastUid = last;
    store.write(
        tx -> {
          tx.remove(new MessageKey(inbox.folderId(), lastUid));
          return null;
        });
    store.compact();
    MetadataStore reopened = reopen(store, MetadataStore.Options.DEFAULT);
    long next = reopened.write(tx -> tx.append(inbox.folderId(), message("k")));
    assertThat(next).isEqualTo(lastUid + 1);
  }

  @Test
  void failedTransactionBodyChangesNothing() throws Exception {
    MetadataStore store = create();
    Folder inbox = store.write(tx -> tx.createFolder("INBOX", SpecialUse.INBOX));
    assertThatThrownBy(
            () ->
                store.write(
                    tx -> {
                      tx.append(inbox.folderId(), message("k"));
                      throw new StorageException(StorageException.Kind.CONFLICT, "abort");
                    }))
        .isInstanceOf(StorageException.class);
    assertThat(uids(store, inbox.folderId())).isEmpty();
    MetadataStore reopened = reopen(store, MetadataStore.Options.DEFAULT);
    assertThat(uids(reopened, inbox.folderId())).isEmpty();
  }

  @Test
  void journalAppendFailureIsNotVisible() throws Exception {
    MetadataStore store = create();
    Folder inbox = store.write(tx -> tx.createFolder("INBOX", SpecialUse.INBOX));
    crashAt.set(MetadataStore.FAULT_BEFORE_APPEND);
    assertThatThrownBy(() -> store.write(tx -> tx.append(inbox.folderId(), message("k"))))
        .isInstanceOf(FaultInjector.SimulatedCrash.class);
    crashAt.set("");
    assertThat(uids(store, inbox.folderId())).isEmpty();
  }

  @Test
  void tornTailRecordIsDiscardedButCorruptCommittedRecordFailsClosed() throws Exception {
    MetadataStore store = create();
    Folder inbox = store.write(tx -> tx.createFolder("INBOX", SpecialUse.INBOX));
    store.write(tx -> tx.append(inbox.folderId(), message("k")));
    store.write(tx -> tx.append(inbox.folderId(), message("k")));
    store.close();
    open.remove(store);
    Path segment = activeSegment();
    byte[] data = Files.readAllBytes(segment);

    // Torn write: the last record is cut short.
    Files.write(segment, java.util.Arrays.copyOf(data, data.length - 10));
    MetadataStore recovered = reopen(null, MetadataStore.Options.DEFAULT);
    assertThat(uids(recovered, inbox.folderId())).containsExactly(1L);
    long uid = recovered.write(tx -> tx.append(inbox.folderId(), message("k")));
    assertThat(uid).isEqualTo(2);
    recovered.close();
    open.remove(recovered);

    // Bit flip inside a complete committed record.
    byte[] current = Files.readAllBytes(segment);
    current[Journal.headerLength() + 10] ^= 1;
    Files.write(segment, current);
    assertThatThrownBy(() -> reopen(null, MetadataStore.Options.DEFAULT))
        .extracting(e -> ((StorageException) e).kind())
        .isEqualTo(StorageException.Kind.CORRUPT);
  }

  @Test
  void missingOrSubstitutedCommittedFilesFailClosed() throws Exception {
    MetadataStore store = create();
    Folder inbox = store.write(tx -> tx.createFolder("INBOX", SpecialUse.INBOX));
    store.write(tx -> tx.append(inbox.folderId(), message("k")));
    store.compact();
    store.close();
    open.remove(store);
    Path snapshot = singleFile("snap-");
    Path moved = dir.resolve("moved");
    Files.move(snapshot, moved);
    assertThatThrownBy(() -> reopen(null, MetadataStore.Options.DEFAULT))
        .extracting(e -> ((StorageException) e).kind())
        .isEqualTo(StorageException.Kind.CORRUPT);
    Files.move(moved, snapshot);
    Files.write(dir.resolve(Manifest.FILE), new byte[] {'S', 'H', 'M', 'M', 1, 1});
    assertThatThrownBy(() -> reopen(null, MetadataStore.Options.DEFAULT))
        .extracting(e -> ((StorageException) e).kind())
        .isEqualTo(StorageException.Kind.CORRUPT);
  }

  @Test
  void wrongDataKeyIsRejected() throws Exception {
    MetadataStore store = create();
    store.write(tx -> tx.createFolder("INBOX", SpecialUse.INBOX));
    store.close();
    open.remove(store);
    try (SymmetricKey wrong = SymmetricKey.generate(RANDOM)) {
      assertThatThrownBy(
              () ->
                  MetadataStore.open(
                      dir, mailbox, v -> Optional.of(wrong), env(MetadataStore.Options.DEFAULT)))
          .extracting(e -> ((StorageException) e).kind())
          .isEqualTo(StorageException.Kind.CORRUPT);
    }
  }

  @Test
  void crashAroundCompactionManifestKeepsAllCommittedData() throws Exception {
    for (String point :
        List.of(MetadataStore.FAULT_BEFORE_MANIFEST, MetadataStore.FAULT_AFTER_MANIFEST)) {
      Path sub = Files.createDirectories(dir.resolve(point.replace('.', '_')));
      MetadataStore store =
          MetadataStore.create(sub, mailbox, root, 1, env(MetadataStore.Options.DEFAULT));
      Folder inbox = store.write(tx -> tx.createFolder("INBOX", SpecialUse.INBOX));
      for (int i = 0; i < 10; i++) {
        store.write(tx -> tx.append(inbox.folderId(), message("k")));
      }
      crashAt.set(point);
      assertThatThrownBy(store::compact).isInstanceOf(FaultInjector.SimulatedCrash.class);
      crashAt.set("");
      store.close();
      try (MetadataStore recovered =
          MetadataStore.open(
              sub, mailbox, v -> Optional.of(root), env(MetadataStore.Options.DEFAULT))) {
        assertThat(uids(recovered, inbox.folderId())).hasSize(10);
        long next = recovered.write(tx -> tx.append(inbox.folderId(), message("k")));
        assertThat(next).isEqualTo(11);
        try (var files = Files.list(sub)) {
          long snapshots =
              files.filter(f -> f.getFileName().toString().startsWith("snap-")).count();
          assertThat(snapshots).isLessThanOrEqualTo(1);
        }
      }
    }
  }

  @Test
  void largeMailboxUsesBoundedCacheAcrossSegmentsAndSnapshots() throws Exception {
    MetadataStore.Options small =
        new MetadataStore.Options(64 * 1024, 3_000, 4, 50_000, Duration.ofDays(1));
    MetadataStore store = MetadataStore.create(dir, mailbox, root, 1, env(small));
    open.add(store);
    Folder inbox = store.write(tx -> tx.createFolder("INBOX", SpecialUse.INBOX));
    Folder other = store.write(tx -> tx.createFolder("Other", SpecialUse.NONE));
    for (int batch = 0; batch < 20; batch++) {
      store.write(
          tx -> {
            for (int i = 0; i < 500; i++) {
              tx.append(inbox.folderId(), message("k"));
            }
            tx.append(other.folderId(), message("o"));
            return null;
          });
    }
    store.write(
        tx ->
            tx.setFlags(new MessageKey(inbox.folderId(), 7), new Flags(Flags.FLAGGED, List.of())));
    MetadataStore reopened = reopen(store, small);
    reopened.read(
        view -> {
          assertThat(view.uids(inbox.folderId())).hasSize(10_000);
          assertThat(view.uids(other.folderId())).hasSize(20);
          assertThat(
                  view.message(new MessageKey(inbox.folderId(), 7))
                      .orElseThrow()
                      .flags()
                      .has(Flags.FLAGGED))
              .isTrue();
          assertThat(view.message(new MessageKey(inbox.folderId(), 9_999))).isPresent();
          assertThat(view.message(new MessageKey(inbox.folderId(), 10_001))).isEmpty();
          return null;
        });
    try (var files = Files.list(dir)) {
      assertThat(files.filter(f -> f.getFileName().toString().startsWith("snap-")).count())
          .isEqualTo(1);
    }
  }

  @Test
  void reencryptionMovesAllStateToNewKeyAndOldKeyNoLongerOpens() throws Exception {
    MetadataStore store = create();
    Folder inbox = store.write(tx -> tx.createFolder("INBOX", SpecialUse.INBOX));
    store.write(tx -> tx.append(inbox.folderId(), message("k")));
    try (SymmetricKey newRoot = SymmetricKey.generate(RANDOM)) {
      store.reencrypt(newRoot, 2);
      assertThat(store.dataVersion()).isEqualTo(2);
      store.write(tx -> tx.append(inbox.folderId(), message("k")));
      store.close();
      open.remove(store);
      assertThatThrownBy(
              () ->
                  MetadataStore.open(
                      dir,
                      mailbox,
                      v -> v == 1 ? Optional.of(root) : Optional.empty(),
                      env(MetadataStore.Options.DEFAULT)))
          .isInstanceOf(StorageException.class);
      try (MetadataStore reopened =
          MetadataStore.open(
              dir,
              mailbox,
              v -> v == 2 ? Optional.of(newRoot) : Optional.empty(),
              env(MetadataStore.Options.DEFAULT))) {
        assertThat(uids(reopened, inbox.folderId())).containsExactly(1L, 2L);
      }
    }
  }

  @Test
  void secondOpenOfSameMailboxIsRejected() throws Exception {
    create();
    assertThatThrownBy(
            () ->
                MetadataStore.open(
                    dir, mailbox, v -> Optional.of(root), env(MetadataStore.Options.DEFAULT)))
        .extracting(e -> ((StorageException) e).kind())
        .isEqualTo(StorageException.Kind.CONFLICT);
  }

  @Test
  void receiptCheckpointsPersistAndAreDeduplicated() throws Exception {
    MetadataStore store = create();
    OpaqueId receipt = OpaqueId.random(RANDOM);
    store.write(
        tx -> {
          tx.markReceiptImported(receipt);
          return null;
        });
    store.compact();
    MetadataStore reopened = reopen(store, MetadataStore.Options.DEFAULT);
    assertThat(reopened.<Boolean>read(v -> v.receiptImported(receipt))).isTrue();
  }

  private static long[] uids(MetadataStore store, OpaqueId folderId) throws StorageException {
    return store.read(v -> v.uids(folderId));
  }

  private Path activeSegment() throws IOException {
    return singleFile("seg-");
  }

  private Path singleFile(String prefix) throws IOException {
    try (var files = Files.list(dir)) {
      List<Path> matches =
          files.filter(f -> f.getFileName().toString().startsWith(prefix)).toList();
      assertThat(matches).hasSize(1);
      return matches.get(0);
    }
  }
}
