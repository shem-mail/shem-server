package org.shem.outbound;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.FileChannel;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.shem.common.DurableFiles;
import org.shem.common.FormatException;
import org.shem.common.IdGenerator;
import org.shem.common.OpaqueId;
import org.shem.common.RecordReader;
import org.shem.common.RecordWriter;
import org.shem.delivery.MessageSource;

/**
 * Durable outbound queue. Each item is {@code <id>.eml} (the exact bytes to transmit, already
 * signed) and {@code <id>.state} (a versioned state record). An item exists once its state file is
 * published; the message file is synced and renamed first, so a crash leaves either a complete item
 * or an orphan message file that {@link #open} removes. State transitions replace the state file
 * atomically. Capacity is bounded by item count and bytes; admission fails temporarily when full.
 *
 * <p>Contents are plaintext by design (ADR 0012); the directory is owner-only and separate from
 * mailbox storage.
 */
public final class OutboundQueue {
  private static final byte[] MAGIC = {'S', 'H', 'O', 'Q'};
  private static final int VERSION = 1;
  private static final int MAX_RECIPIENTS = 1000;

  /** Capacity limits. */
  public record Limits(int maxItems, long maxBytes, Duration lifetime) {}

  /** The queue cannot accept more mail right now. */
  public static final class QueueFullException extends Exception {
    private static final long serialVersionUID = 1L;

    public QueueFullException() {
      super("outbound queue full");
    }
  }

  private final Path directory;
  private final Limits limits;
  private final IdGenerator ids;
  private final Clock clock;
  private final Map<OpaqueId, QueueItem> items = new ConcurrentHashMap<>();
  private final Map<OpaqueId, Long> sizes = new ConcurrentHashMap<>();
  private final Object admission = new Object();

  private OutboundQueue(Path directory, Limits limits, IdGenerator ids, Clock clock) {
    this.directory = directory;
    this.limits = limits;
    this.ids = ids;
    this.clock = clock;
  }

  /** Opens the queue, removing temporary and orphaned files left by a crash. */
  public static OutboundQueue open(Path directory, Limits limits, IdGenerator ids, Clock clock)
      throws IOException {
    DurableFiles.createPrivateDirectories(directory);
    OutboundQueue queue = new OutboundQueue(directory, limits, ids, clock);
    List<Path> orphans = new ArrayList<>();
    try (DirectoryStream<Path> files = Files.newDirectoryStream(directory)) {
      for (Path file : files) {
        String name = file.getFileName().toString();
        if (name.startsWith(DurableFiles.TEMP_PREFIX)) {
          orphans.add(file);
        } else if (name.endsWith(".state")) {
          queue.load(file);
        }
      }
    }
    try (DirectoryStream<Path> files = Files.newDirectoryStream(directory, "*.eml")) {
      for (Path file : files) {
        String name = file.getFileName().toString();
        OpaqueId id = OpaqueId.parseOrNull(name.substring(0, name.length() - 4));
        if (id == null || !queue.items.containsKey(id)) {
          orphans.add(file);
        }
      }
    }
    for (Path orphan : orphans) {
      Files.deleteIfExists(orphan);
    }
    DurableFiles.syncDirectory(directory);
    return queue;
  }

  private void load(Path stateFile) throws IOException {
    QueueItem item;
    try {
      item = decode(Files.readAllBytes(stateFile));
    } catch (FormatException e) {
      throw new IOException("corrupt queue state " + stateFile.getFileName(), e);
    }
    Path message = messageFile(item.id());
    if (!Files.exists(message)) {
      throw new IOException("queue item without message " + stateFile.getFileName());
    }
    items.put(item.id(), item);
    sizes.put(item.id(), Files.size(message));
  }

  /**
   * Durably queues {@code message} for {@code recipients}. Returns only after the message and its
   * state are synced and published.
   */
  public QueueItem enqueue(String sender, List<String> recipients, MessageSource message)
      throws IOException, QueueFullException {
    if (recipients.isEmpty() || recipients.size() > MAX_RECIPIENTS) {
      throw new IllegalArgumentException("recipient count out of range");
    }
    OpaqueId id = ids.next();
    synchronized (admission) {
      if (items.size() >= limits.maxItems() || usedBytes() + message.size() > limits.maxBytes()) {
        throw new QueueFullException();
      }
      sizes.put(id, message.size());
    }
    boolean published = false;
    try {
      Path temp = DurableFiles.createTemporarySibling(messageFile(id));
      try {
        try (FileChannel channel = FileChannel.open(temp, StandardOpenOption.WRITE);
            OutputStream out = DurableFiles.syncingOutputStream(channel);
            InputStream in = message.open()) {
          in.transferTo(out);
        }
        DurableFiles.publish(temp, messageFile(id), false);
      } finally {
        Files.deleteIfExists(temp);
      }
      Instant now = clock.instant();
      List<QueueItem.Recipient> state = new ArrayList<>();
      for (String recipient : recipients) {
        state.add(new QueueItem.Recipient(recipient, QueueItem.Status.PENDING, ""));
      }
      QueueItem item =
          new QueueItem(id, sender, state, now, now.plus(limits.lifetime()), now, 0, false);
      DurableFiles.writeNew(stateFile(id), encode(item));
      items.put(id, item);
      published = true;
      return item;
    } finally {
      if (!published) {
        sizes.remove(id);
        Files.deleteIfExists(messageFile(id));
      }
    }
  }

  /** Durably records a new state for an existing item. */
  public void update(QueueItem item) throws IOException {
    if (!items.containsKey(item.id())) {
      throw new IllegalStateException("unknown queue item");
    }
    DurableFiles.writeAtomically(stateFile(item.id()), encode(item));
    items.put(item.id(), item);
  }

  /** Removes a finished item: state first, so a crash never resurrects a removed item. */
  public void remove(OpaqueId id) throws IOException {
    DurableFiles.deleteDurably(stateFile(id));
    items.remove(id);
    Files.deleteIfExists(messageFile(id));
    sizes.remove(id);
  }

  /** Items whose next attempt is due, oldest first. */
  public List<QueueItem> due(Instant now) {
    return items.values().stream()
        .filter(i -> !i.nextAttempt().isAfter(now))
        .sorted(Comparator.comparing(QueueItem::nextAttempt))
        .toList();
  }

  public Optional<QueueItem> get(OpaqueId id) {
    return Optional.ofNullable(items.get(id));
  }

  public int size() {
    return items.size();
  }

  /** The exact bytes to transmit. */
  public InputStream openMessage(OpaqueId id) throws IOException {
    return Files.newInputStream(messageFile(id));
  }

  private long usedBytes() {
    long total = 0;
    for (long size : sizes.values()) {
      total += size;
    }
    return total;
  }

  private Path messageFile(OpaqueId id) {
    return directory.resolve(id + ".eml");
  }

  private Path stateFile(OpaqueId id) {
    return directory.resolve(id + ".state");
  }

  static byte[] encode(QueueItem item) {
    RecordWriter w =
        new RecordWriter()
            .raw(MAGIC)
            .u8(VERSION)
            .id(item.id())
            .string(item.sender())
            .i64(item.created().toEpochMilli())
            .i64(item.expires().toEpochMilli())
            .i64(item.nextAttempt().toEpochMilli())
            .u32(item.attempts())
            .bool(item.notified())
            .u16(item.recipients().size());
    for (QueueItem.Recipient r : item.recipients()) {
      w.string(r.address()).u8(code(r.status())).string(r.lastReply());
    }
    return w.toByteArray();
  }

  /** Persisted status codes; never reuse a value. */
  private static int code(QueueItem.Status status) {
    return switch (status) {
      case PENDING -> 1;
      case DELIVERED -> 2;
      case FAILED -> 3;
    };
  }

  static QueueItem decode(byte[] data) throws FormatException {
    RecordReader r = new RecordReader(data);
    byte[] magic = r.raw(4);
    if (!java.util.Arrays.equals(magic, MAGIC)) {
      throw new FormatException("not a queue state record");
    }
    int version = r.u8();
    if (version != VERSION) {
      throw new FormatException("unsupported queue state version " + version);
    }
    OpaqueId id = r.id();
    String sender = r.string(320);
    Instant created = Instant.ofEpochMilli(r.i64());
    Instant expires = Instant.ofEpochMilli(r.i64());
    Instant next = Instant.ofEpochMilli(r.i64());
    int attempts = (int) r.u32();
    boolean notified = r.bool();
    int count = r.u16();
    if (count == 0 || count > MAX_RECIPIENTS) {
      throw new FormatException("recipient count out of range");
    }
    List<QueueItem.Recipient> recipients = new ArrayList<>();
    for (int i = 0; i < count; i++) {
      String address = r.string(320);
      QueueItem.Status status =
          switch (r.u8()) {
            case 1 -> QueueItem.Status.PENDING;
            case 2 -> QueueItem.Status.DELIVERED;
            case 3 -> QueueItem.Status.FAILED;
            default -> throw new FormatException("unknown recipient status");
          };
      recipients.add(new QueueItem.Recipient(address, status, r.string(256)));
    }
    r.expectEnd();
    return new QueueItem(id, sender, recipients, created, expires, next, attempts, notified);
  }
}
