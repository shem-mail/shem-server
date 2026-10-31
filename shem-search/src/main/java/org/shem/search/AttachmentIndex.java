package org.shem.search;

import java.io.IOException;
import java.io.InputStream;
import java.lang.System.Logger.Level;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import org.apache.lucene.document.Document;
import org.apache.lucene.document.Field;
import org.apache.lucene.document.StoredField;
import org.apache.lucene.document.StringField;
import org.apache.lucene.document.TextField;
import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.index.IndexWriter;
import org.apache.lucene.index.IndexWriterConfig;
import org.apache.lucene.index.StoredFields;
import org.apache.lucene.index.Term;
import org.apache.lucene.search.BooleanClause;
import org.apache.lucene.search.BooleanQuery;
import org.apache.lucene.search.IndexSearcher;
import org.apache.lucene.search.ScoreDoc;
import org.apache.lucene.search.TermQuery;
import org.apache.lucene.search.TopDocs;
import org.apache.lucene.store.NIOFSDirectory;
import org.shem.common.DurableFiles;
import org.shem.common.OpaqueId;
import org.shem.crypto.CryptoException;
import org.shem.crypto.Purpose;
import org.shem.crypto.SymmetricKey;
import org.shem.mailbox.ExtensionContext;
import org.shem.mailbox.MailboxExtension;
import org.shem.store.StorageException;
import org.shem.store.metadata.Folder;
import org.shem.store.metadata.MessageKey;
import org.shem.store.metadata.MessageRecord;
import org.shem.store.metadata.MetadataChange;

/**
 * Encrypted per-mailbox index of attachment text trigrams (ADR 0019), separate from {@link
 * SearchIndex} so standard IMAP search and attachment search never share coverage. Every message
 * gets one document once its attachments were processed: {@code complete} when every attachment in
 * the supported scope yielded full text (or there were none), {@code incomplete} when one was
 * encrypted, truncated, over a limit, or failed. Text is never stored, only trigrams. A message
 * whose extraction could not run at all (no worker) gets no document and stays pending.
 */
public final class AttachmentIndex implements MailboxExtension {
  private static final System.Logger LOG = System.getLogger(AttachmentIndex.class.getName());
  static final String BLOB = "blob";
  static final String STATUS = "status";
  static final String GRAMS = "a";
  static final int MAX_ATTACHMENTS = 32;
  private static final String VERSION_FILE = "data-version";
  private static final int MAX_QUERY_GRAMS = 64;

  private final ExtensionContext context;
  private final AttachmentExtractor extractor;
  private final EncryptedDirectory directory;
  private final IndexWriter writer;
  private final AutoCloseable subscription;
  private final Object queueLock = new Object();
  private final ArrayDeque<Pending> queue = new ArrayDeque<>();
  private final Set<OpaqueId> queued = new HashSet<>();
  private final AtomicBoolean draining = new AtomicBoolean();
  private volatile Snapshot snapshot;
  private volatile boolean closed;

  private record Pending(MessageKey key, OpaqueId blobId) {}

  /** A committed reader with exactly the blob ids it covers and those covered incompletely. */
  public static final class Snapshot {
    private final DirectoryReader reader;
    private final Set<OpaqueId> covered;
    private final Set<OpaqueId> incomplete;

    Snapshot(DirectoryReader reader, Set<OpaqueId> covered, Set<OpaqueId> incomplete) {
      this.reader = reader;
      this.covered = Set.copyOf(covered);
      this.incomplete = Set.copyOf(incomplete);
    }

    public boolean covers(OpaqueId blobId) {
      return covered.contains(blobId);
    }

    /** Covered, but some attachment could not be searched completely. */
    public boolean incomplete(OpaqueId blobId) {
      return incomplete.contains(blobId);
    }
  }

  private AttachmentIndex(
      ExtensionContext context,
      AttachmentExtractor extractor,
      EncryptedDirectory directory,
      IndexWriter writer)
      throws IOException {
    this.context = context;
    this.extractor = extractor;
    this.directory = directory;
    this.writer = writer;
    DirectoryReader reader = DirectoryReader.open(writer);
    this.snapshot = load(reader);
    this.subscription = context.subscribe((txSeq, origin, changes) -> onChanges(changes));
  }

  static AttachmentIndex open(ExtensionContext context, AttachmentExtractor extractor)
      throws StorageException, CryptoException {
    Path path = context.directory();
    try {
      prepare(path, context.dataVersion());
      try (SymmetricKey key = context.deriveKey(Purpose.ATTACHMENT_INDEX)) {
        EncryptedDirectory directory =
            new EncryptedDirectory(new NIOFSDirectory(path), key, context.mailboxId());
        IndexWriter writer;
        try {
          writer = new IndexWriter(directory, new IndexWriterConfig().setCommitOnClose(false));
        } catch (IOException e) {
          directory.close();
          wipe(path);
          prepare(path, context.dataVersion());
          directory = new EncryptedDirectory(new NIOFSDirectory(path), key, context.mailboxId());
          writer = new IndexWriter(directory, new IndexWriterConfig().setCommitOnClose(false));
        }
        AttachmentIndex index = new AttachmentIndex(context, extractor, directory, writer);
        index.enqueueUncovered();
        return index;
      }
    } catch (IOException e) {
      throw new StorageException(
          StorageException.Kind.UNAVAILABLE, "attachment index unavailable", e);
    }
  }

  private static void prepare(Path path, int dataVersion) throws IOException {
    DurableFiles.createPrivateDirectories(path);
    Path marker = path.resolve(VERSION_FILE);
    String expected = Integer.toString(dataVersion);
    if (Files.exists(marker) && !Files.readString(marker).equals(expected)) {
      wipe(path);
      DurableFiles.createPrivateDirectories(path);
    }
    if (!Files.exists(marker)) {
      DurableFiles.writeAtomically(
          marker, expected.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
    }
  }

  private static void wipe(Path path) throws IOException {
    if (!Files.exists(path)) {
      return;
    }
    try (var files = Files.walk(path)) {
      for (Path p : (Iterable<Path>) files.sorted(java.util.Comparator.reverseOrder())::iterator) {
        Files.deleteIfExists(p);
      }
    }
  }

  public Snapshot acquire() {
    while (true) {
      Snapshot current = snapshot;
      if (current.reader.tryIncRef()) {
        return current;
      }
    }
  }

  public void release(Snapshot s) {
    try {
      s.reader.decRef();
    } catch (IOException e) {
      LOG.log(Level.WARNING, "attachment reader release failed");
    }
  }

  /**
   * Covered blob ids whose attachment text contains every trigram of {@code value} (after
   * whitespace collapsing, case-insensitive). This is a superset of exact phrase matches: the text
   * is not stored, so matches cannot be verified. Empty when the value is shorter than three
   * characters (the caller must reject such queries).
   */
  public Optional<Set<OpaqueId>> matches(Snapshot s, String value) throws IOException {
    Set<String> grams = SearchText.attachmentQueryGrams(value);
    if (grams.isEmpty()) {
      return Optional.empty();
    }
    BooleanQuery.Builder query = new BooleanQuery.Builder();
    int added = 0;
    for (String gram : grams) {
      if (added++ == MAX_QUERY_GRAMS) {
        break;
      }
      query.add(new TermQuery(new Term(GRAMS, gram)), BooleanClause.Occur.MUST);
    }
    IndexSearcher searcher = new IndexSearcher(s.reader);
    TopDocs hits = searcher.search(query.build(), Math.max(1, s.reader.maxDoc()));
    Set<OpaqueId> result = new HashSet<>();
    StoredFields stored = searcher.storedFields();
    for (ScoreDoc hit : hits.scoreDocs) {
      String blob = stored.document(hit.doc).get(BLOB);
      OpaqueId id = blob == null ? null : OpaqueId.parseOrNull(blob);
      if (id != null) {
        result.add(id);
      }
    }
    return Optional.of(result);
  }

  // ---- indexing ----

  private void onChanges(List<MetadataChange> changes) {
    boolean added = false;
    synchronized (queueLock) {
      for (MetadataChange change : changes) {
        if (change instanceof MetadataChange.MessageAdded a) {
          added |= enqueue(a.key(), a.record().blobId());
        }
      }
    }
    if (added) {
      scheduleDrain();
    }
  }

  private boolean enqueue(MessageKey key, OpaqueId blobId) {
    if (snapshot.covers(blobId) || !queued.add(blobId)) {
      return false;
    }
    queue.add(new Pending(key, blobId));
    return true;
  }

  private void enqueueUncovered() throws StorageException {
    Snapshot current = snapshot;
    synchronized (queueLock) {
      context.read(
          view -> {
            for (Folder folder : view.folders()) {
              view.forEachMessage(
                  folder.folderId(),
                  (uid, record) -> {
                    if (!current.covers(record.blobId())) {
                      enqueue(new MessageKey(folder.folderId(), uid), record.blobId());
                    }
                    return true;
                  });
            }
            return null;
          });
    }
    scheduleDrain();
  }

  /** Re-queues pending work, for example after the extractor became available again. */
  public void retry() throws StorageException {
    enqueueUncovered();
  }

  /**
   * Extraction mostly waits on worker processes, so the drain runs on a virtual thread; the
   * extractor's own worker limit bounds real concurrency.
   */
  private void scheduleDrain() {
    if (draining.compareAndSet(false, true)) {
      Thread.ofVirtual().name("shem-attachments").start(this::drain);
    }
  }

  void drain() {
    try {
      while (!closed && context.isOpen()) {
        Pending next;
        synchronized (queueLock) {
          next = queue.poll();
        }
        if (next == null) {
          return;
        }
        if (!indexOne(next)) {
          return;
        }
      }
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    } catch (IOException | StorageException | RuntimeException e) {
      if (!closed && context.isOpen()) {
        LOG.log(Level.WARNING, "attachment indexing paused: " + e.getClass().getSimpleName());
      }
    } finally {
      draining.set(false);
    }
  }

  /** Returns false when extraction is unavailable; the message then stays pending. */
  private boolean indexOne(Pending pending)
      throws IOException, StorageException, InterruptedException {
    OpaqueId blobId = pending.blobId();
    Optional<MessageRecord> record = context.read(view -> view.message(pending.key()));
    if (record.isEmpty() || !record.get().blobId().equals(blobId)) {
      synchronized (queueLock) {
        queued.remove(blobId);
      }
      return true;
    }
    List<String> texts = new ArrayList<>();
    boolean[] incomplete = new boolean[1];
    int[] count = new int[1];
    try (InputStream in = context.openMessage(record.get())) {
      AttachmentParts.walk(
          in,
          (type, extension, decoded) -> {
            if (++count[0] > MAX_ATTACHMENTS) {
              incomplete[0] = true;
              return false;
            }
            if (outOfScope(type)) {
              return true;
            }
            AttachmentExtractor.Outcome outcome = extractor.extract(decoded, type, extension);
            switch (outcome) {
              case AttachmentExtractor.Outcome.Text t -> {
                texts.add(t.text());
                incomplete[0] |= t.truncated();
              }
              case AttachmentExtractor.Outcome.Unsupported u -> {}
              default -> incomplete[0] = true;
            }
            return true;
          });
    } catch (AttachmentExtractor.UnavailableException e) {
      synchronized (queueLock) {
        queued.remove(blobId);
      }
      return false;
    } catch (AttachmentParts.MalformedException e) {
      incomplete[0] = true;
    }
    Set<String> grams = SearchText.attachmentGrams(texts);
    if (grams == null) {
      grams = Set.of();
      incomplete[0] = true;
    }
    Document doc = new Document();
    doc.add(new StringField(BLOB, blobId.value(), Field.Store.NO));
    doc.add(new StoredField(BLOB, blobId.value()));
    doc.add(new StoredField(STATUS, incomplete[0] ? "incomplete" : "complete"));
    doc.add(new TextField(GRAMS, new GramTokenStream(grams)));
    writer.updateDocument(new Term(BLOB, blobId.value()), doc);
    writer.commit();
    publish(blobId, incomplete[0]);
    synchronized (queueLock) {
      queued.remove(blobId);
    }
    return true;
  }

  /**
   * Media the extractor has no parser for by design (images, audio, video): not part of the
   * promised attachment-search scope, so they neither reach a worker nor make a message incomplete.
   */
  static boolean outOfScope(String mimeType) {
    return mimeType.startsWith("image/")
        || mimeType.startsWith("audio/")
        || mimeType.startsWith("video/");
  }

  private synchronized void publish(OpaqueId blobId, boolean incomplete) throws IOException {
    Snapshot previous = snapshot;
    DirectoryReader next = DirectoryReader.openIfChanged(previous.reader, writer);
    if (next == null) {
      return;
    }
    Set<OpaqueId> covered = new HashSet<>(previous.covered);
    covered.add(blobId);
    Set<OpaqueId> partial = new HashSet<>(previous.incomplete);
    if (incomplete) {
      partial.add(blobId);
    } else {
      partial.remove(blobId);
    }
    snapshot = new Snapshot(next, covered, partial);
    previous.reader.decRef();
  }

  private static Snapshot load(DirectoryReader reader) throws IOException {
    Set<OpaqueId> covered = new HashSet<>();
    Set<OpaqueId> incomplete = new HashSet<>();
    StoredFields stored = reader.storedFields();
    for (int doc = 0; doc < reader.maxDoc(); doc++) {
      Document document = stored.document(doc);
      String blob = document.get(BLOB);
      OpaqueId id = blob == null ? null : OpaqueId.parseOrNull(blob);
      if (id != null) {
        covered.add(id);
        if ("incomplete".equals(document.get(STATUS))) {
          incomplete.add(id);
        }
      }
    }
    return new Snapshot(reader, covered, incomplete);
  }

  /** Waits until the queue is empty (tests). */
  public boolean awaitIdle(java.time.Duration timeout) throws InterruptedException {
    long deadline = System.nanoTime() + timeout.toNanos();
    while (System.nanoTime() < deadline) {
      boolean empty;
      synchronized (queueLock) {
        empty = queue.isEmpty();
      }
      if (empty && !draining.get()) {
        return true;
      }
      Thread.sleep(10);
    }
    return false;
  }

  @Override
  public void close() {
    closed = true;
    try {
      subscription.close();
    } catch (Exception e) {
      LOG.log(Level.WARNING, "attachment subscription close failed");
    }
    synchronized (this) {
      try {
        snapshot.reader.decRef();
        writer.rollback();
        directory.close();
      } catch (IOException e) {
        LOG.log(Level.WARNING, "attachment index close failed");
      }
    }
  }
}
