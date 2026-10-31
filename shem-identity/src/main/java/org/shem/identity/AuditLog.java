package org.shem.identity;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.regex.Pattern;
import org.jspecify.annotations.Nullable;
import org.shem.common.DurableFiles;

/**
 * Append-only, hash-chained audit trail of identity and administration changes (ADR 0020). Each
 * line is {@code v1 seq time actor action target outcome prev hash}, where {@code hash} is the
 * SHA-256 of everything before it and {@code prev} the previous line's hash. Fields are restricted
 * to opaque tokens: administrator names, opaque mailbox/domain/alias ids, and fixed action names,
 * never addresses, subjects, or credentials.
 *
 * <p>The chain detects edits and deletions inside the file, not truncation of its tail or
 * replacement of the whole file by someone who controls the disk: for that, mirror records to an
 * independently controlled sink ({@code mirror}, for example stdout collected by journald and
 * forwarded off-host).
 *
 * <p>Callers append an {@code attempt} record before a change and the outcome after; if the attempt
 * cannot be made durable, the change must not happen (fail closed).
 */
public final class AuditLog implements AutoCloseable {
  static final String GENESIS = "0".repeat(64);
  private static final Pattern TOKEN = Pattern.compile("[A-Za-z0-9:._@-]{1,128}");

  /** Thrown when existing records do not form a valid chain. */
  public static final class BrokenChainException extends Exception {
    private static final long serialVersionUID = 1L;

    BrokenChainException(String message) {
      super(message);
    }
  }

  private final Path file;
  private final Clock clock;
  private final @Nullable PrintStream mirror;
  private final FileChannel channel;
  private long seq;
  private String last;

  private AuditLog(
      Path file,
      Clock clock,
      @Nullable PrintStream mirror,
      FileChannel channel,
      long seq,
      String last) {
    this.file = file;
    this.clock = clock;
    this.mirror = mirror;
    this.channel = channel;
    this.seq = seq;
    this.last = last;
  }

  /**
   * Opens the log, verifying the whole chain. A final line without a newline is a write that never
   * completed (the change it announced was refused), so it is cut off; any other inconsistency
   * fails.
   */
  public static AuditLog open(Path file, Clock clock, @Nullable PrintStream mirror)
      throws IOException, BrokenChainException {
    DurableFiles.createPrivateDirectories(java.util.Objects.requireNonNull(file.getParent()));
    if (!Files.exists(file)) {
      Files.createFile(
          file, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
    }
    byte[] content = Files.readAllBytes(file);
    int complete = content.length;
    while (complete > 0 && content[complete - 1] != '\n') {
      complete--;
    }
    String text = new String(content, 0, complete, StandardCharsets.UTF_8);
    Verified verified = verify(text);
    FileChannel channel = FileChannel.open(file, StandardOpenOption.WRITE);
    if (complete < content.length) {
      channel.truncate(complete);
      channel.force(true);
    }
    channel.position(complete);
    return new AuditLog(file, clock, mirror, channel, verified.seq(), verified.last());
  }

  record Verified(long seq, String last) {}

  /** Checks every line's hash and link; returns the last sequence number and hash. */
  static Verified verify(String text) throws BrokenChainException {
    long seq = 0;
    String last = GENESIS;
    List<String> lines = text.isEmpty() ? List.of() : List.of(text.split("\n", -1));
    for (int i = 0; i < lines.size(); i++) {
      String line = lines.get(i);
      if (line.isEmpty() && i == lines.size() - 1) {
        break;
      }
      String[] fields = line.split(" ", -1);
      if (fields.length != 9 || !fields[0].equals("v1")) {
        throw new BrokenChainException("audit record " + (i + 1) + " is malformed");
      }
      long recordSeq;
      try {
        recordSeq = Long.parseLong(fields[1]);
      } catch (NumberFormatException e) {
        throw new BrokenChainException("audit record " + (i + 1) + " is malformed");
      }
      if (recordSeq != seq + 1 || !fields[7].equals(last)) {
        throw new BrokenChainException("audit chain broken at record " + (i + 1));
      }
      String body = line.substring(0, line.lastIndexOf(' '));
      if (!sha256(body).equals(fields[8])) {
        throw new BrokenChainException("audit record " + (i + 1) + " was modified");
      }
      seq = recordSeq;
      last = fields[8];
    }
    return new Verified(seq, last);
  }

  /** Verifies a log file without opening it for writing (CLI). Returns the record count. */
  public static long verifyFile(Path file) throws IOException, BrokenChainException {
    if (!Files.exists(file)) {
      return 0;
    }
    String text = Files.readString(file, StandardCharsets.UTF_8);
    int end = text.lastIndexOf('\n') + 1;
    return verify(text.substring(0, end)).seq();
  }

  /**
   * Appends and fsyncs one record. Throws if it cannot be made durable; callers then refuse the
   * change it describes.
   */
  public synchronized void record(String actor, String action, String target, String outcome)
      throws IOException {
    String body =
        "v1 "
            + (seq + 1)
            + " "
            + clock.instant().truncatedTo(java.time.temporal.ChronoUnit.MILLIS)
            + " "
            + token(actor)
            + " "
            + token(action)
            + " "
            + token(target)
            + " "
            + token(outcome)
            + " "
            + last;
    String hash = sha256(body);
    String line = body + " " + hash + "\n";
    ByteBuffer buffer = ByteBuffer.wrap(line.getBytes(StandardCharsets.UTF_8));
    while (buffer.hasRemaining()) {
      channel.write(buffer);
    }
    channel.force(true);
    seq++;
    last = hash;
    PrintStream sink = mirror;
    if (sink != null) {
      sink.print("audit " + line);
      sink.flush();
    }
  }

  /** Replaces anything outside the token alphabet so a record can never carry free text. */
  static String token(String value) {
    return TOKEN.matcher(value).matches() ? value : "invalid";
  }

  static String sha256(String text) {
    try {
      return HexFormat.of()
          .formatHex(
              MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8)));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 unavailable", e);
    }
  }

  public Path file() {
    return file;
  }

  public synchronized long size() {
    return seq;
  }

  public Instant now() {
    return clock.instant();
  }

  @Override
  public synchronized void close() throws IOException {
    channel.close();
  }
}
