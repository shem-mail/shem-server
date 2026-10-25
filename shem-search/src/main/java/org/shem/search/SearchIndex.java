package org.shem.search;

import java.io.IOException;
import java.io.InputStream;
import java.lang.System.Logger.Level;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
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
 * Encrypted per-mailbox index of message trigrams keyed by blob id (content is immutable per blob,
 * so COPY/MOVE need no reindexing). Coverage is published together with the Lucene reader that
 * contains it, so a search always sees a consistent pair. Flags and folder membership are never
 * indexed; they come from metadata at search time.
 */
public final class SearchIndex implements MailboxExtension {
  private static final System.Logger LOG = System.getLogger(SearchIndex.class.getName());
  static final String BLOB = "blob";
  static final String BODY = "b";
  static final String TEXT = "t";
  private static final String VERSION_FILE = "data-version";
  private static final int BATCH = 50;
  private static final int MAX_QUERY_GRAMS = 64;

  private final ExtensionContext context;
  private final EncryptedDirectory directory;
  private final IndexWriter writer;
  private final AutoCloseable subscription;
  private final Object queueLock = new Object();
  private final ArrayDeque<Pending> queue = new ArrayDeque<>();
  private final Set<OpaqueId> queued = new HashSet<>();
  private final Set<OpaqueId> unindexable = new HashSet<>();
  private final AtomicBoolean draining = new AtomicBoolean();
  private volatile Snapshot snapshot;
  private volatile boolean closed;

  private record Pending(MessageKey key, OpaqueId blobId) {}

  /** A committed reader and exactly the blob ids it covers. */
  public static final class Snapshot {
    private final DirectoryReader reader;
    private final Set<OpaqueId> covered;

    Snapshot(DirectoryReader reader, Set<OpaqueId> covered) {
      this.reader = reader;
      this.covered = Set.copyOf(covered);
    }

    public boolean covers(OpaqueId blobId) {
      return covered.contains(blobId);
    }

    public int coveredCount() {
      return covered.size();
    }
  }

  private SearchIndex(ExtensionContext context, EncryptedDirectory directory, IndexWriter writer)
      throws IOException {
    this.context = context;
    this.directory = directory;
    this.writer = writer;
    DirectoryReader reader = DirectoryReader.open(writer);
    this.snapshot = new Snapshot(reader, storedBlobs(reader));
    this.subscription = context.subscribe((txSeq, origin, changes) -> onChanges(changes));
  }

  static SearchIndex open(ExtensionContext context) throws StorageException, CryptoException {
    Path path = context.directory();
    try {
      prepare(path, context.dataVersion());
      try (SymmetricKey key = context.deriveKey(Purpose.SEARCH_INDEX)) {
        EncryptedDirectory directory =
            new EncryptedDirectory(new NIOFSDirectory(path), key, context.mailboxId());
        IndexWriter writer;
        try {
          writer = new IndexWriter(directory, new IndexWriterConfig().setCommitOnClose(false));
        } catch (IOException e) {
          // Corrupt or undecryptable index: it is derived data, so rebuild from scratch.
          directory.close();
          wipe(path);
          prepare(path, context.dataVersion());
          directory = new EncryptedDirectory(new NIOFSDirectory(path), key, context.mailboxId());
          writer = new IndexWriter(directory, new IndexWriterConfig().setCommitOnClose(false));
        }
        SearchIndex index = new SearchIndex(context, directory, writer);
        index.enqueueUncovered();
        return index;
      }
    } catch (IOException e) {
      throw new StorageException(StorageException.Kind.UNAVAILABLE, "search index unavailable", e);
    }
  }

  /** Keeps the index only if it was built under the current data version. */
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

  /** The current committed snapshot; callers must {@link #release} it. */
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
      LOG.log(Level.WARNING, "search reader release failed");
    }
  }

  /**
   * Blob ids in {@code snapshot} whose indexed text can contain {@code value} in the given field.
   * Returns empty when the index cannot narrow the search (value shorter than a trigram).
   */
  public Optional<Set<OpaqueId>> candidates(Snapshot s, String value, boolean includeHeaders)
      throws IOException {
    Set<String> grams = SearchText.queryGrams(value);
    if (grams.isEmpty()) {
      return Optional.empty();
    }
    BooleanQuery.Builder query = new BooleanQuery.Builder();
    int added = 0;
    for (String gram : grams) {
      if (added++ == MAX_QUERY_GRAMS) {
        break; // fewer constraints still yields a superset
      }
      query.add(
          new TermQuery(new Term(includeHeaders ? TEXT : BODY, gram)), BooleanClause.Occur.MUST);
    }
    IndexSearcher searcher = new IndexSearcher(s.reader);
    int max = Math.max(1, s.reader.maxDoc());
    TopDocs hits = searcher.search(query.build(), max);
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
    if (snapshot.covers(blobId) || unindexable.contains(blobId) || !queued.add(blobId)) {
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

  private void scheduleDrain() {
    if (draining.compareAndSet(false, true)) {
      try {
        context.executor().execute(this::drain);
      } catch (RuntimeException e) {
        draining.set(false);
      }
    }
  }

  /** Indexes queued messages in batches; each batch is committed before coverage grows. */
  void drain() {
    try {
      while (!closed && context.isOpen()) {
        List<Pending> batch = new java.util.ArrayList<>();
        synchronized (queueLock) {
          while (batch.size() < BATCH && !queue.isEmpty()) {
            batch.add(queue.poll());
          }
        }
        if (batch.isEmpty()) {
          return;
        }
        indexBatch(batch);
      }
    } catch (IOException | StorageException | RuntimeException e) {
      LOG.log(Level.WARNING, "search indexing paused: " + e.getClass().getSimpleName());
    } finally {
      draining.set(false);
      boolean more;
      synchronized (queueLock) {
        more = !queue.isEmpty();
      }
      if (more && !closed && context.isOpen()) {
        scheduleDrain();
      }
    }
  }

  private void indexBatch(List<Pending> batch) throws IOException, StorageException {
    Set<OpaqueId> covered = new HashSet<>();
    for (Pending pending : batch) {
      Optional<MessageRecord> record = context.read(view -> view.message(pending.key()));
      OpaqueId blobId = pending.blobId();
      if (record.isEmpty() || !record.get().blobId().equals(blobId)) {
        synchronized (queueLock) {
          queued.remove(blobId); // expunged meanwhile; another reference re-enqueues it
        }
        continue;
      }
      SearchText.Grams grams;
      try (InputStream in = context.openMessage(record.get())) {
        grams = SearchText.extract(in);
      } catch (IOException | StorageException e) {
        grams = null; // failed extraction never advances coverage
      }
      synchronized (queueLock) {
        queued.remove(blobId);
        if (grams == null) {
          unindexable.add(blobId);
          continue;
        }
      }
      Document doc = new Document();
      doc.add(new StringField(BLOB, blobId.value(), Field.Store.NO));
      doc.add(new StoredField(BLOB, blobId.value()));
      doc.add(new TextField(BODY, new GramTokenStream(grams.body())));
      doc.add(new TextField(TEXT, new GramTokenStream(grams.text())));
      writer.updateDocument(new Term(BLOB, blobId.value()), doc);
      covered.add(blobId);
    }
    if (covered.isEmpty()) {
      return;
    }
    writer.commit();
    publish(covered);
  }

  private synchronized void publish(Set<OpaqueId> added) throws IOException {
    Snapshot previous = snapshot;
    DirectoryReader next = DirectoryReader.openIfChanged(previous.reader, writer);
    if (next == null) {
      return;
    }
    Set<OpaqueId> covered = new HashSet<>(previous.covered);
    covered.addAll(added);
    snapshot = new Snapshot(next, covered);
    previous.reader.decRef();
  }

  private static Set<OpaqueId> storedBlobs(DirectoryReader reader) throws IOException {
    Set<OpaqueId> result = new HashSet<>();
    StoredFields stored = reader.storedFields();
    for (int doc = 0; doc < reader.maxDoc(); doc++) {
      String blob = stored.document(doc).get(BLOB);
      OpaqueId id = blob == null ? null : OpaqueId.parseOrNull(blob);
      if (id != null) {
        result.add(id);
      }
    }
    return result;
  }

  /** Waits until the queue is empty (tests and benchmarks). */
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
      LOG.log(Level.WARNING, "search subscription close failed");
    }
    synchronized (this) {
      try {
        snapshot.reader.decRef();
        writer.rollback();
        directory.close();
      } catch (IOException e) {
        LOG.log(Level.WARNING, "search index close failed");
      }
    }
  }
}
