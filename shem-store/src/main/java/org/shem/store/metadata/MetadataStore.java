package org.shem.store.metadata;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.NavigableMap;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.IntFunction;
import org.jspecify.annotations.Nullable;
import org.shem.common.DurableFiles;
import org.shem.common.FaultInjector;
import org.shem.common.FormatException;
import org.shem.common.IdGenerator;
import org.shem.common.ImmutableBytes;
import org.shem.common.OpaqueId;
import org.shem.common.RecordReader;
import org.shem.common.RecordWriter;
import org.shem.crypto.CryptoException;
import org.shem.crypto.Purpose;
import org.shem.crypto.SymmetricKey;
import org.shem.store.SpecialUse;
import org.shem.store.StorageException;

/**
 * Encrypted metadata store for one mailbox. One instance per mailbox per process (enforced with a
 * file lock); transactions are serialized by a write lock and become durable before they become
 * visible.
 */
public final class MetadataStore implements AutoCloseable {
  public static final String FAULT_BEFORE_MANIFEST = "metadata.before-manifest";
  public static final String FAULT_AFTER_MANIFEST = "metadata.after-manifest";
  public static final String FAULT_BEFORE_APPEND = "metadata.before-append";

  /** Tunables; all bounded. */
  public record Options(
      long maxSegmentBytes,
      long compactAfterOps,
      int cacheBlocks,
      int maxOpsPerTransaction,
      Duration receiptCheckpointRetention) {
    public static final Options DEFAULT =
        new Options(4L << 20, 20_000, 256, 50_000, Duration.ofDays(400));
  }

  /** Transaction body. */
  @FunctionalInterface
  public interface TxBody<T extends @Nullable Object> {
    T run(Tx tx) throws StorageException;
  }

  /** Read body. */
  @FunctionalInterface
  public interface ReadBody<T extends @Nullable Object> {
    T run(ReadView view) throws StorageException;
  }

  private final Path directory;
  private final OpaqueId mailboxId;
  private final Options options;
  private final IdGenerator ids;
  private final SecureRandom random;
  private final Clock clock;
  private final FaultInjector faults;
  private final FileChannel lockChannel;
  private final FileLock lock;
  private final ReentrantReadWriteLock rw = new ReentrantReadWriteLock();

  private SymmetricKey dataRoot;
  private Manifest manifest;
  private @Nullable SnapshotReader snapshot;
  private MailboxState state;
  private Journal.Writer active;
  private final Set<String> pinned = new HashSet<>();
  private boolean closed;

  private MetadataStore(
      Path directory,
      OpaqueId mailboxId,
      Options options,
      IdGenerator ids,
      SecureRandom random,
      Clock clock,
      FaultInjector faults,
      FileChannel lockChannel,
      FileLock lock,
      SymmetricKey dataRoot,
      Manifest manifest,
      @Nullable SnapshotReader snapshot,
      MailboxState state,
      Journal.Writer active) {
    this.directory = directory;
    this.mailboxId = mailboxId;
    this.options = options;
    this.ids = ids;
    this.random = random;
    this.clock = clock;
    this.faults = faults;
    this.lockChannel = lockChannel;
    this.lock = lock;
    this.dataRoot = dataRoot;
    this.manifest = manifest;
    this.snapshot = snapshot;
    this.state = state;
    this.active = active;
  }

  /** Environment shared by create/open. */
  public record Environment(
      IdGenerator ids, SecureRandom random, Clock clock, FaultInjector faults, Options options) {}

  /** Initializes an empty store. Takes a copy of {@code dataRoot}. */
  public static MetadataStore create(
      Path directory, OpaqueId mailboxId, SymmetricKey dataRoot, int dataVersion, Environment env)
      throws StorageException {
    try {
      DurableFiles.createPrivateDirectories(directory);
      if (Files.exists(directory.resolve(Manifest.FILE))) {
        throw new StorageException(StorageException.Kind.CONFLICT, "metadata already exists");
      }
      OpaqueId segment = env.ids().next();
      Journal.Writer.create(
              directory.resolve(Journal.fileName(segment)),
              mailboxId,
              segment,
              dataVersion,
              dataRoot)
          .close();
      Manifest manifest = new Manifest(1, dataVersion, null, List.of(), segment);
      DurableFiles.writeNew(directory.resolve(Manifest.FILE), manifest.seal(mailboxId, dataRoot));
    } catch (IOException e) {
      throw new StorageException(StorageException.Kind.UNAVAILABLE, "metadata init failed", e);
    } catch (CryptoException e) {
      throw new StorageException(StorageException.Kind.UNAVAILABLE, "metadata init failed", e);
    }
    return open(
        directory,
        mailboxId,
        v -> v == dataVersion ? Optional.of(dataRoot) : Optional.empty(),
        env);
  }

  /**
   * Opens and recovers a store. {@code dataRoots} supplies the data root for the manifest's data
   * version; the store keeps its own copy. Corrupt committed state fails with {@link
   * StorageException.Kind#CORRUPT}; a torn final journal record is discarded.
   */
  public static MetadataStore open(
      Path directory,
      OpaqueId mailboxId,
      IntFunction<Optional<SymmetricKey>> dataRoots,
      Environment env)
      throws StorageException {
    FileChannel lockChannel = null;
    FileLock lock = null;
    SymmetricKey root = null;
    SnapshotReader snapshot = null;
    try {
      lockChannel =
          FileChannel.open(
              directory.resolve("lock"), StandardOpenOption.CREATE, StandardOpenOption.WRITE);
      try {
        lock = lockChannel.tryLock();
      } catch (OverlappingFileLockException e) {
        lock = null;
      }
      if (lock == null) {
        throw new StorageException(StorageException.Kind.CONFLICT, "metadata store already open");
      }
      byte[] sealedManifest = Files.readAllBytes(directory.resolve(Manifest.FILE));
      int dataVersion = Manifest.dataVersionOf(sealedManifest, mailboxId);
      root =
          dataRoots
              .apply(dataVersion)
              .orElseThrow(
                  () -> new StorageException(StorageException.Kind.CORRUPT, "data key unavailable"))
              .copy();
      Manifest manifest = Manifest.open(sealedManifest, mailboxId, root);

      MailboxState state;
      if (manifest.snapshotId() != null) {
        try (SymmetricKey fileKey = snapshotKey(root, manifest.snapshotId())) {
          snapshot =
              SnapshotReader.open(
                  directory.resolve(Manifest.snapshotFile(manifest.snapshotId())),
                  fileKey,
                  Manifest.snapshotContext(mailboxId, manifest.snapshotId()),
                  env.options().cacheBlocks());
        }
        state = copyTables(snapshot.tables);
      } else {
        state = new MailboxState();
      }
      state.deltaOps = 0;
      for (OpaqueId segment : manifest.sealedSegments()) {
        Journal.Contents contents =
            Journal.read(
                directory.resolve(Journal.fileName(segment)),
                mailboxId,
                segment,
                dataVersion,
                root);
        if (!contents.sealed() || contents.tornTail()) {
          throw new StorageException(StorageException.Kind.CORRUPT, "sealed segment incomplete");
        }
        replay(state, contents.payloads(), snapshot);
      }
      Journal.Contents tail =
          Journal.read(
              directory.resolve(Journal.fileName(manifest.activeSegment())),
              mailboxId,
              manifest.activeSegment(),
              dataVersion,
              root);
      replay(state, tail.payloads(), snapshot);
      Journal.Writer writer =
          Journal.Writer.reopen(
              directory.resolve(Journal.fileName(manifest.activeSegment())),
              mailboxId,
              manifest.activeSegment(),
              root,
              tail.payloads().size(),
              tail.validLength());
      MetadataStore store =
          new MetadataStore(
              directory,
              mailboxId,
              env.options(),
              env.ids(),
              env.random(),
              env.clock(),
              env.faults(),
              lockChannel,
              lock,
              root,
              manifest,
              snapshot,
              state,
              writer);
      if (tail.sealed()) {
        store.rollSegment();
      }
      store.deleteUnreferencedFiles();
      return store;
    } catch (NoSuchFileException e) {
      cleanup(snapshot, root, lock, lockChannel);
      throw new StorageException(
          StorageException.Kind.CORRUPT, "committed metadata file missing", e);
    } catch (IOException e) {
      cleanup(snapshot, root, lock, lockChannel);
      throw new StorageException(StorageException.Kind.UNAVAILABLE, "metadata open failed", e);
    } catch (FormatException | CryptoException e) {
      cleanup(snapshot, root, lock, lockChannel);
      throw new StorageException(StorageException.Kind.CORRUPT, "metadata failed verification", e);
    } catch (StorageException | RuntimeException e) {
      cleanup(snapshot, root, lock, lockChannel);
      throw e;
    }
  }

  public OpaqueId mailboxId() {
    return mailboxId;
  }

  public int dataVersion() {
    rw.readLock().lock();
    try {
      return manifest.dataVersion();
    } finally {
      rw.readLock().unlock();
    }
  }

  public <T extends @Nullable Object> T read(ReadBody<T> body) throws StorageException {
    rw.readLock().lock();
    try {
      checkOpen();
      return body.run(new View(state, snapshot, null));
    } catch (SnapshotReader.CorruptSnapshotException e) {
      throw new StorageException(StorageException.Kind.CORRUPT, "snapshot block corrupt", e);
    } finally {
      rw.readLock().unlock();
    }
  }

  public <T extends @Nullable Object> T write(TxBody<T> body) throws StorageException {
    rw.writeLock().lock();
    try {
      checkOpen();
      TxImpl tx = new TxImpl(state, snapshot);
      T result = body.run(tx);
      if (tx.ops.isEmpty()) {
        return result;
      }
      if (tx.ops.size() > options.maxOpsPerTransaction()) {
        throw new StorageException(StorageException.Kind.LIMIT_EXCEEDED, "transaction too large");
      }
      long txSeq = state.txSeq + 1;
      RecordWriter payload = new RecordWriter().u8(Journal.TYPE_TX).i64(txSeq).u32(tx.ops.size());
      tx.ops.forEach(op -> Codec.op(payload, op));
      byte[] bytes = payload.toByteArrayAndWipe();
      if (bytes.length > Journal.MAX_RECORD) {
        throw new StorageException(StorageException.Kind.LIMIT_EXCEEDED, "transaction too large");
      }
      try {
        faults.at(FAULT_BEFORE_APPEND);
        active.append(bytes);
      } catch (IOException | CryptoException e) {
        throw new StorageException(StorageException.Kind.UNAVAILABLE, "journal append failed", e);
      } finally {
        java.util.Arrays.fill(bytes, (byte) 0);
      }
      state.txSeq = txSeq;
      for (Op op : tx.ops) {
        state.apply(op, snapshot);
      }
      maintain();
      return result;
    } catch (SnapshotReader.CorruptSnapshotException e) {
      throw new StorageException(StorageException.Kind.CORRUPT, "snapshot block corrupt", e);
    } finally {
      rw.writeLock().unlock();
    }
  }

  /** Folds the journal into a new snapshot under the current data root. */
  public void compact() throws StorageException {
    rw.writeLock().lock();
    try {
      checkOpen();
      compactLocked(null, manifest.dataVersion());
    } finally {
      rw.writeLock().unlock();
    }
  }

  /**
   * Re-encrypts all metadata under a new data root (rotation/enrollment). Old snapshot and segment
   * files are removed after the new manifest is durable, except while pinned by a backup.
   */
  public void reencrypt(SymmetricKey newDataRoot, int newDataVersion) throws StorageException {
    rw.writeLock().lock();
    try {
      checkOpen();
      if (newDataVersion <= manifest.dataVersion()) {
        throw new StorageException(StorageException.Kind.CONFLICT, "data version must increase");
      }
      compactLocked(newDataRoot.copy(), newDataVersion);
    } finally {
      rw.writeLock().unlock();
    }
  }

  /** Blob ids referenced by any live message (full scan; used by garbage collection). */
  public Set<OpaqueId> referencedBlobs() throws StorageException {
    return read(
        view -> {
          Set<OpaqueId> result = new HashSet<>();
          for (Folder folder : view.folders()) {
            view.forEachMessage(
                folder.folderId(),
                (uid, record) -> {
                  result.add(record.blobId());
                  return true;
                });
          }
          return result;
        });
  }

  /** Files of the current commit, for consistent backups. Pins them until {@link #unpin()}. */
  public List<Path> pinCurrentFiles() throws StorageException {
    rw.writeLock().lock();
    try {
      checkOpen();
      try {
        rollSegment();
      } catch (IOException | CryptoException e) {
        throw new StorageException(StorageException.Kind.UNAVAILABLE, "segment roll failed", e);
      }
      List<Path> files = new ArrayList<>();
      files.add(directory.resolve(Manifest.FILE));
      if (manifest.snapshotId() != null) {
        files.add(directory.resolve(Manifest.snapshotFile(manifest.snapshotId())));
      }
      for (OpaqueId segment : manifest.sealedSegments()) {
        files.add(directory.resolve(Journal.fileName(segment)));
      }
      files.add(directory.resolve(Journal.fileName(manifest.activeSegment())));
      for (Path file : files) {
        pinned.add(String.valueOf(file.getFileName()));
      }
      return files;
    } finally {
      rw.writeLock().unlock();
    }
  }

  public void unpin() throws StorageException {
    rw.writeLock().lock();
    try {
      pinned.clear();
      if (!closed) {
        deleteUnreferencedFiles();
      }
    } finally {
      rw.writeLock().unlock();
    }
  }

  @Override
  public void close() throws StorageException {
    rw.writeLock().lock();
    try {
      if (closed) {
        return;
      }
      closed = true;
      StorageException failure = null;
      try {
        active.close();
      } catch (IOException e) {
        failure =
            new StorageException(StorageException.Kind.UNAVAILABLE, "journal close failed", e);
      }
      if (snapshot != null) {
        snapshot.close();
      }
      state = new MailboxState();
      dataRoot.close();
      try {
        lock.release();
        lockChannel.close();
      } catch (IOException e) {
        if (failure == null) {
          failure =
              new StorageException(StorageException.Kind.UNAVAILABLE, "lock release failed", e);
        }
      }
      if (failure != null) {
        throw failure;
      }
    } finally {
      rw.writeLock().unlock();
    }
  }

  // ---- internals ----

  private void maintain() throws StorageException {
    try {
      if (state.deltaOps >= options.compactAfterOps()) {
        compactLocked(null, manifest.dataVersion());
      } else if (active.length() >= options.maxSegmentBytes()) {
        rollSegment();
      }
    } catch (IOException | CryptoException e) {
      throw new StorageException(StorageException.Kind.UNAVAILABLE, "segment roll failed", e);
    }
  }

  /** Seals the active segment and starts a new one (committed via a new manifest). */
  private void rollSegment() throws IOException, CryptoException {
    OpaqueId next = ids.next();
    Journal.Writer writer =
        Journal.Writer.create(
            directory.resolve(Journal.fileName(next)),
            mailboxId,
            next,
            manifest.dataVersion(),
            dataRoot);
    try {
      if (!isSealed(manifest.activeSegment())) {
        active.seal();
      }
      List<OpaqueId> sealed = new ArrayList<>(manifest.sealedSegments());
      sealed.add(manifest.activeSegment());
      Manifest updated =
          new Manifest(
              manifest.generation() + 1,
              manifest.dataVersion(),
              manifest.snapshotId(),
              sealed,
              next);
      publishManifest(updated, dataRoot);
      active.close();
      active = writer;
      manifest = updated;
    } catch (IOException | CryptoException | RuntimeException e) {
      writer.close();
      throw e;
    }
  }

  private boolean isSealed(OpaqueId segment) throws IOException, CryptoException {
    try {
      return Journal.read(
              directory.resolve(Journal.fileName(segment)),
              mailboxId,
              segment,
              manifest.dataVersion(),
              dataRoot)
          .sealed();
    } catch (FormatException e) {
      throw new IOException("active segment unreadable", e);
    }
  }

  private void compactLocked(@Nullable SymmetricKey newRoot, int targetVersion)
      throws StorageException {
    SymmetricKey writeRoot = newRoot != null ? newRoot : dataRoot;
    OpaqueId snapshotId = ids.next();
    OpaqueId segmentId = ids.next();
    Path snapshotPath = directory.resolve(Manifest.snapshotFile(snapshotId));
    Journal.Writer writer = null;
    try {
      MailboxState tables = copyTables(state);
      long cutoff = clock.millis() - options.receiptCheckpointRetention().toMillis();
      tables.importedReceipts.values().removeIf(at -> at < cutoff);
      try (SymmetricKey fileKey = snapshotKey(writeRoot, snapshotId)) {
        SnapshotWriter.write(
            snapshotPath,
            fileKey,
            Manifest.snapshotContext(mailboxId, snapshotId),
            state.txSeq,
            tables,
            allLiveMessages());
      }
      writer =
          Journal.Writer.create(
              directory.resolve(Journal.fileName(segmentId)),
              mailboxId,
              segmentId,
              targetVersion,
              writeRoot);
      Manifest updated =
          new Manifest(manifest.generation() + 1, targetVersion, snapshotId, List.of(), segmentId);
      faults.at(FAULT_BEFORE_MANIFEST);
      publishManifest(updated, writeRoot);
      faults.at(FAULT_AFTER_MANIFEST);
      SnapshotReader reader;
      try (SymmetricKey fileKey = snapshotKey(writeRoot, snapshotId)) {
        reader =
            SnapshotReader.open(
                snapshotPath,
                fileKey,
                Manifest.snapshotContext(mailboxId, snapshotId),
                options.cacheBlocks());
      }
      active.close();
      if (snapshot != null) {
        snapshot.close();
      }
      active = writer;
      writer = null;
      snapshot = reader;
      MailboxState fresh = copyTables(reader.tables);
      fresh.txSeq = state.txSeq;
      state = fresh;
      manifest = updated;
      if (newRoot != null) {
        dataRoot.close();
        dataRoot = newRoot;
        newRoot = null;
      }
      deleteUnreferencedFiles();
    } catch (IOException | CryptoException e) {
      throw new StorageException(StorageException.Kind.UNAVAILABLE, "compaction failed", e);
    } finally {
      if (writer != null) {
        try {
          writer.close();
        } catch (IOException ignored) {
          // The unpublished segment is removed as unreferenced on the next open.
        }
      }
      if (newRoot != null) {
        newRoot.close();
      }
    }
  }

  private Iterator<Map.Entry<MessageKey, MessageRecord>> allLiveMessages() {
    List<OpaqueId> folderIds = new ArrayList<>(state.folders.keySet());
    folderIds.sort(null);
    View view = new View(state, snapshot, null);
    Iterator<OpaqueId> folders = folderIds.iterator();
    return new Iterator<>() {
      Iterator<Map.Entry<MessageKey, MessageRecord>> current =
          java.util.Collections.emptyIterator();

      @Override
      public boolean hasNext() {
        while (!current.hasNext() && folders.hasNext()) {
          current = view.merged(folders.next());
        }
        return current.hasNext();
      }

      @Override
      public Map.Entry<MessageKey, MessageRecord> next() {
        if (!hasNext()) {
          throw new java.util.NoSuchElementException();
        }
        return current.next();
      }
    };
  }

  private void publishManifest(Manifest updated, SymmetricKey root)
      throws IOException, CryptoException {
    DurableFiles.writeAtomically(directory.resolve(Manifest.FILE), updated.seal(mailboxId, root));
  }

  private void deleteUnreferencedFiles() throws StorageException {
    Set<String> live = new HashSet<>(pinned);
    live.add(Manifest.FILE);
    live.add("lock");
    if (manifest.snapshotId() != null) {
      live.add(Manifest.snapshotFile(manifest.snapshotId()));
    }
    manifest.sealedSegments().forEach(s -> live.add(Journal.fileName(s)));
    live.add(Journal.fileName(manifest.activeSegment()));
    try (var files = Files.list(directory)) {
      for (Path file : (Iterable<Path>) files::iterator) {
        String name = String.valueOf(file.getFileName());
        if (!live.contains(name)
            && (name.startsWith("seg-")
                || name.startsWith("snap-")
                || name.startsWith(DurableFiles.TEMP_PREFIX))) {
          Files.deleteIfExists(file);
        }
      }
      DurableFiles.syncDirectory(directory);
    } catch (IOException e) {
      throw new StorageException(StorageException.Kind.UNAVAILABLE, "metadata cleanup failed", e);
    }
  }

  private static void replay(
      MailboxState state, List<byte[]> payloads, @Nullable SnapshotReader base)
      throws FormatException {
    for (byte[] payload : payloads) {
      RecordReader in = new RecordReader(payload);
      if (in.u8() != Journal.TYPE_TX) {
        throw new FormatException("unexpected journal record");
      }
      long txSeq = in.i64();
      long count = in.u32();
      if (txSeq <= state.txSeq) {
        continue; // already contained in the snapshot
      }
      if (txSeq != state.txSeq + 1) {
        throw new FormatException("journal transaction gap");
      }
      List<Op> ops = new ArrayList<>();
      for (long i = 0; i < count; i++) {
        ops.add(Codec.op(in));
      }
      in.expectEnd();
      state.txSeq = txSeq;
      for (Op op : ops) {
        state.apply(op, base);
      }
      java.util.Arrays.fill(payload, (byte) 0);
    }
  }

  private static SymmetricKey snapshotKey(SymmetricKey root, OpaqueId snapshotId)
      throws CryptoException {
    return root.derive(Purpose.METADATA_SNAPSHOT, snapshotId.toBytes());
  }

  private static MailboxState copyTables(MailboxState source) {
    MailboxState copy = new MailboxState();
    copy.txSeq = source.txSeq;
    copy.modSeq = source.modSeq;
    copy.folders.putAll(source.folders);
    copy.subscriptions.addAll(source.subscriptions);
    copy.properties.putAll(source.properties);
    copy.importedReceipts.putAll(source.importedReceipts);
    return copy;
  }

  private void checkOpen() throws StorageException {
    if (closed) {
      throw new StorageException(StorageException.Kind.UNAVAILABLE, "metadata store closed");
    }
  }

  private static void cleanup(
      @Nullable SnapshotReader snapshot,
      @Nullable SymmetricKey root,
      @Nullable FileLock lock,
      @Nullable FileChannel channel) {
    if (snapshot != null) {
      snapshot.close();
    }
    if (root != null) {
      root.close();
    }
    try {
      if (lock != null) {
        lock.release();
      }
      if (channel != null) {
        channel.close();
      }
    } catch (IOException ignored) {
      // Already failing.
    }
  }

  /** Read view layering an optional transaction overlay over state and snapshot. */
  private static class View implements ReadView {
    final MailboxState state;
    final @Nullable SnapshotReader base;
    final @Nullable TxImpl tx;

    View(MailboxState state, @Nullable SnapshotReader base, @Nullable TxImpl tx) {
      this.state = state;
      this.base = base;
      this.tx = tx;
    }

    Map<OpaqueId, Folder> folderMap() {
      return tx != null ? tx.folders : state.folders;
    }

    @Override
    public long txSeq() {
      return state.txSeq;
    }

    @Override
    public long highestModSeq() {
      return tx != null ? tx.modSeq : state.modSeq;
    }

    @Override
    public Collection<Folder> folders() {
      return List.copyOf(folderMap().values());
    }

    @Override
    public Optional<Folder> folder(OpaqueId folderId) {
      return Optional.ofNullable(folderMap().get(folderId));
    }

    @Override
    public Optional<Folder> folderByName(String name) {
      return folderMap().values().stream().filter(f -> f.name().equals(name)).findFirst();
    }

    @Override
    public Optional<Folder> folderByRole(SpecialUse role) {
      return folderMap().values().stream()
          .filter(f -> f.specialUse() == role)
          .min(java.util.Comparator.comparing(Folder::folderId));
    }

    @Override
    public Set<String> subscriptions() {
      return Set.copyOf(tx != null ? tx.subscriptions : state.subscriptions);
    }

    @Override
    public Optional<MessageRecord> message(MessageKey key) {
      if (!folderMap().containsKey(key.folderId())) {
        return Optional.empty();
      }
      if (tx != null) {
        MessageRecord local = tx.delta.get(key);
        if (local != null) {
          return MailboxState.isTombstone(local) ? Optional.empty() : Optional.of(local);
        }
      }
      MessageRecord changed = state.delta.get(key);
      if (changed != null) {
        return MailboxState.isTombstone(changed) ? Optional.empty() : Optional.of(changed);
      }
      return base == null ? Optional.empty() : base.lookup(key);
    }

    @Override
    public long[] uids(OpaqueId folderId) {
      List<Long> uids = new ArrayList<>();
      merged(folderId).forEachRemaining(e -> uids.add(e.getKey().uid()));
      long[] result = new long[uids.size()];
      for (int i = 0; i < result.length; i++) {
        result[i] = uids.get(i);
      }
      return result;
    }

    @Override
    public void forEachMessage(OpaqueId folderId, MessageVisitor visitor) throws StorageException {
      Iterator<Map.Entry<MessageKey, MessageRecord>> it = merged(folderId);
      while (it.hasNext()) {
        Map.Entry<MessageKey, MessageRecord> e = it.next();
        if (!visitor.visit(e.getKey().uid(), e.getValue())) {
          return;
        }
      }
    }

    /** Live entries of a folder in UID order: tx overlay over state delta over snapshot. */
    Iterator<Map.Entry<MessageKey, MessageRecord>> merged(OpaqueId folderId) {
      if (!folderMap().containsKey(folderId)) {
        return java.util.Collections.emptyIterator();
      }
      MessageKey from = MessageKey.first(folderId);
      MessageKey to = MessageKey.last(folderId);
      NavigableMap<MessageKey, MessageRecord> overlay =
          new TreeMap<>(state.delta.subMap(from, true, to, true));
      if (tx != null) {
        overlay.putAll(tx.delta.subMap(from, true, to, true));
      }
      Iterator<Map.Entry<MessageKey, MessageRecord>> baseIt =
          base == null ? java.util.Collections.emptyIterator() : base.range(from, to);
      Iterator<Map.Entry<MessageKey, MessageRecord>> overIt = overlay.entrySet().iterator();
      return new Iterator<>() {
        Map.@Nullable Entry<MessageKey, MessageRecord> b = baseIt.hasNext() ? baseIt.next() : null;
        Map.@Nullable Entry<MessageKey, MessageRecord> o = overIt.hasNext() ? overIt.next() : null;
        Map.@Nullable Entry<MessageKey, MessageRecord> pending = advance();

        private Map.@Nullable Entry<MessageKey, MessageRecord> advance() {
          while (b != null || o != null) {
            Map.Entry<MessageKey, MessageRecord> candidate;
            if (o == null || (b != null && b.getKey().compareTo(o.getKey()) < 0)) {
              candidate = java.util.Objects.requireNonNull(b);
              b = baseIt.hasNext() ? baseIt.next() : null;
            } else {
              if (b != null && b.getKey().equals(o.getKey())) {
                b = baseIt.hasNext() ? baseIt.next() : null;
              }
              candidate = o;
              o = overIt.hasNext() ? overIt.next() : null;
            }
            if (!MailboxState.isTombstone(candidate.getValue())) {
              return candidate;
            }
          }
          return null;
        }

        @Override
        public boolean hasNext() {
          return pending != null;
        }

        @Override
        public Map.Entry<MessageKey, MessageRecord> next() {
          Map.Entry<MessageKey, MessageRecord> result = pending;
          if (result == null) {
            throw new java.util.NoSuchElementException();
          }
          pending = advance();
          return result;
        }
      };
    }

    @Override
    public boolean receiptImported(OpaqueId receiptId) {
      return (tx != null ? tx.receipts : state.importedReceipts).containsKey(receiptId);
    }

    @Override
    public Map<OpaqueId, Long> importedReceipts() {
      return Map.copyOf(tx != null ? tx.receipts : state.importedReceipts);
    }

    @Override
    public Optional<ImmutableBytes> property(String key) {
      return Optional.ofNullable((tx != null ? tx.properties : state.properties).get(key));
    }
  }

  private final class TxImpl extends View implements Tx {
    final List<Op> ops = new ArrayList<>();
    final Map<OpaqueId, Folder> folders;
    final Set<String> subscriptions;
    final Map<String, ImmutableBytes> properties;
    final Map<OpaqueId, Long> receipts;
    final NavigableMap<MessageKey, MessageRecord> delta = new TreeMap<>();
    long modSeq;

    TxImpl(MailboxState state, @Nullable SnapshotReader base) {
      super(state, base, null);
      this.folders = new HashMap<>(state.folders);
      this.subscriptions = new TreeSet<>(state.subscriptions);
      this.properties = new TreeMap<>(state.properties);
      this.receipts = new HashMap<>(state.importedReceipts);
      this.modSeq = state.modSeq;
    }

    @Override
    Map<OpaqueId, Folder> folderMap() {
      return folders;
    }

    @Override
    public long highestModSeq() {
      return modSeq;
    }

    @Override
    public Set<String> subscriptions() {
      return Set.copyOf(subscriptions);
    }

    @Override
    public Optional<MessageRecord> message(MessageKey key) {
      if (!folders.containsKey(key.folderId())) {
        return Optional.empty();
      }
      MessageRecord local = delta.get(key);
      if (local != null) {
        return MailboxState.isTombstone(local) ? Optional.empty() : Optional.of(local);
      }
      return new View(state, base, null).message(key);
    }

    @Override
    Iterator<Map.Entry<MessageKey, MessageRecord>> merged(OpaqueId folderId) {
      if (!folders.containsKey(folderId)) {
        return java.util.Collections.emptyIterator();
      }
      return new View(state, base, this).merged(folderId);
    }

    @Override
    public boolean receiptImported(OpaqueId receiptId) {
      return receipts.containsKey(receiptId);
    }

    @Override
    public Map<OpaqueId, Long> importedReceipts() {
      return Map.copyOf(receipts);
    }

    @Override
    public Optional<ImmutableBytes> property(String key) {
      return Optional.ofNullable(properties.get(key));
    }

    @Override
    public Folder createFolder(String name, SpecialUse specialUse) throws StorageException {
      if (folderByName(name).isPresent()) {
        throw new StorageException(StorageException.Kind.CONFLICT, "folder exists");
      }
      long uidValidity;
      do {
        uidValidity = random.nextInt() & 0xffffffffL;
      } while (uidValidity == 0);
      Folder folder;
      try {
        folder = new Folder(ids.next(), name, uidValidity, 1, specialUse);
      } catch (IllegalArgumentException e) {
        throw new StorageException(StorageException.Kind.LIMIT_EXCEEDED, "invalid folder", e);
      }
      folders.put(folder.folderId(), folder);
      ops.add(new Op.CreateFolder(folder));
      return folder;
    }

    @Override
    public void renameFolder(OpaqueId folderId, String newName) throws StorageException {
      Folder folder = requireFolder(folderId);
      Optional<Folder> clash = folderByName(newName);
      if (clash.isPresent() && !clash.get().folderId().equals(folderId)) {
        throw new StorageException(StorageException.Kind.CONFLICT, "folder exists");
      }
      try {
        folders.put(folderId, folder.withName(newName));
      } catch (IllegalArgumentException e) {
        throw new StorageException(StorageException.Kind.LIMIT_EXCEEDED, "invalid folder name", e);
      }
      ops.add(new Op.RenameFolder(folderId, newName));
    }

    @Override
    public void deleteFolder(OpaqueId folderId) throws StorageException {
      requireFolder(folderId);
      folders.remove(folderId);
      delta.subMap(MessageKey.first(folderId), true, MessageKey.last(folderId), true).clear();
      ops.add(new Op.DeleteFolder(folderId));
    }

    @Override
    public void setSubscribed(String name, boolean subscribed) {
      if (subscribed) {
        subscriptions.add(name);
      } else {
        subscriptions.remove(name);
      }
      ops.add(new Op.Subscribe(name, subscribed));
    }

    @Override
    public long append(OpaqueId folderId, NewMessage m) throws StorageException {
      Folder folder = requireFolder(folderId);
      long uid = folder.uidNext();
      if (uid > 0xffffffffL) {
        throw new StorageException(StorageException.Kind.LIMIT_EXCEEDED, "UID space exhausted");
      }
      MessageRecord record;
      try {
        record =
            new MessageRecord(
                m.blobId(),
                m.wrappedContentKey(),
                m.size(),
                m.internalDateMillis(),
                ++modSeq,
                m.flags(),
                m.summary());
      } catch (IllegalArgumentException e) {
        throw new StorageException(StorageException.Kind.LIMIT_EXCEEDED, "invalid message", e);
      }
      MessageKey key = new MessageKey(folderId, uid);
      folders.put(folderId, folder.withUidNext(uid + 1));
      delta.put(key, record);
      ops.add(new Op.PutMessage(key, record));
      return uid;
    }

    @Override
    public long copy(MessageKey source, OpaqueId destinationFolder) throws StorageException {
      MessageRecord record =
          message(source)
              .orElseThrow(
                  () -> new StorageException(StorageException.Kind.NOT_FOUND, "no message"));
      return append(
          destinationFolder,
          new NewMessage(
              record.blobId(),
              record.wrappedContentKey(),
              record.size(),
              record.internalDateMillis(),
              record.flags(),
              record.summary()));
    }

    @Override
    public long setFlags(MessageKey key, Flags flags) throws StorageException {
      MessageRecord record =
          message(key)
              .orElseThrow(
                  () -> new StorageException(StorageException.Kind.NOT_FOUND, "no message"));
      long next = ++modSeq;
      delta.put(key, record.withFlags(flags, next));
      ops.add(new Op.SetFlags(key, flags, next));
      return next;
    }

    @Override
    public void remove(MessageKey key) throws StorageException {
      if (message(key).isEmpty()) {
        throw new StorageException(StorageException.Kind.NOT_FOUND, "no message");
      }
      delta.put(key, MailboxState.TOMBSTONE);
      ops.add(new Op.RemoveMessage(key, ++modSeq));
    }

    @Override
    public void markReceiptImported(OpaqueId receiptId) {
      long now = clock.millis();
      receipts.put(receiptId, now);
      ops.add(new Op.ReceiptImported(receiptId, now));
    }

    @Override
    public void forgetReceipt(OpaqueId receiptId) {
      receipts.remove(receiptId);
      ops.add(new Op.ForgetReceipt(receiptId));
    }

    @Override
    public void setProperty(String key, ImmutableBytes value) {
      if (value.length() == 0) {
        properties.remove(key);
      } else {
        properties.put(key, value);
      }
      ops.add(new Op.SetProperty(key, value));
    }

    private Folder requireFolder(OpaqueId folderId) throws StorageException {
      Folder folder = folders.get(folderId);
      if (folder == null) {
        throw new StorageException(StorageException.Kind.NOT_FOUND, "no folder");
      }
      return folder;
    }
  }
}
