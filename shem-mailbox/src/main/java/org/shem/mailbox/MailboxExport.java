package org.shem.mailbox;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.shem.store.StorageException;
import org.shem.store.metadata.Flags;
import org.shem.store.metadata.Folder;
import org.shem.store.metadata.MessageKey;
import org.shem.store.metadata.MessageRecord;

/**
 * Plaintext export of a whole mailbox as a ZIP stream (format {@value #FORMAT}, ADR 0017):
 *
 * <ul>
 *   <li>{@code folders/N.mbox}: one mboxrd file per folder, messages in UID order, bytes unchanged
 *       apart from {@code >From } quoting. Entry names are indexes, so folder names never become
 *       paths.
 *   <li>{@code manifest.json}, written last: format, export time, and per folder its name, special
 *       use, UIDVALIDITY, and per message UID, flags, keywords, and internal date.
 * </ul>
 *
 * <p>Nothing is staged on disk: messages are decrypted, quoted, and compressed straight into the
 * caller's stream. Memory is bounded by the UID list of one folder plus the manifest (a few dozen
 * bytes per message). Each message is re-read by key, so messages expunged during the export are
 * skipped and the export never holds the metadata read lock while writing.
 */
public final class MailboxExport {
  public static final String FORMAT = "shem-mbox-zip-v1";

  private static final DateTimeFormatter FROM_DATE =
      DateTimeFormatter.ofPattern("EEE MMM ppd HH:mm:ss yyyy", Locale.ROOT)
          .withZone(ZoneOffset.UTC);
  private static final byte[] FROM = "From ".getBytes(StandardCharsets.US_ASCII);

  private MailboxExport() {}

  /** What an export wrote. */
  public record Summary(int folders, long messages) {}

  /**
   * Writes the export of {@code lease}'s mailbox to {@code out}, which is finished but not closed.
   * Stops with {@link IOException} if the client disconnects and with {@link RevokedLeaseException}
   * if the lease is revoked; either way no partial state remains anywhere but in the caller's
   * stream.
   */
  public static Summary write(MailboxLease lease, OutputStream out, Instant now)
      throws IOException, StorageException {
    List<Folder> folders =
        lease.read(
            view ->
                new ArrayList<>(view.folders())
                    .stream().sorted((a, b) -> a.name().compareTo(b.name())).toList());
    ZipOutputStream zip = new ZipOutputStream(out, StandardCharsets.UTF_8);
    StringBuilder manifest = new StringBuilder(256);
    manifest
        .append("{\"format\":\"")
        .append(FORMAT)
        .append("\",\"exportedAt\":\"")
        .append(now)
        .append("\",\"folders\":[");
    long messages = 0;
    for (int index = 0; index < folders.size(); index++) {
      Folder folder = folders.get(index);
      long[] uids =
          lease.read(
              view ->
                  view.folder(folder.folderId()).isPresent()
                      ? view.uids(folder.folderId())
                      : new long[0]);
      String file = "folders/" + index + ".mbox";
      zip.putNextEntry(new ZipEntry(file));
      if (index > 0) {
        manifest.append(',');
      }
      manifest.append("{\"name\":");
      quote(manifest, folder.name());
      manifest
          .append(",\"specialUse\":\"")
          .append(folder.specialUse().name().toLowerCase(Locale.ROOT))
          .append("\",\"uidValidity\":")
          .append(folder.uidValidity())
          .append(",\"file\":\"")
          .append(file)
          .append("\",\"messages\":[");
      boolean first = true;
      for (long uid : uids) {
        MessageKey key = new MessageKey(folder.folderId(), uid);
        Optional<MessageRecord> record = lease.read(view -> view.message(key));
        if (record.isEmpty()) {
          continue;
        }
        writeMessage(lease, record.get(), zip);
        if (!first) {
          manifest.append(',');
        }
        first = false;
        manifestEntry(manifest, uid, record.get());
        messages++;
      }
      manifest.append("]}");
      zip.closeEntry();
    }
    manifest.append("]}\n");
    zip.putNextEntry(new ZipEntry("manifest.json"));
    zip.write(manifest.toString().getBytes(StandardCharsets.UTF_8));
    zip.closeEntry();
    zip.finish();
    return new Summary(folders.size(), messages);
  }

  private static void writeMessage(MailboxLease lease, MessageRecord record, OutputStream out)
      throws IOException, StorageException {
    String from =
        "From MAILER-DAEMON "
            + FROM_DATE.format(Instant.ofEpochMilli(record.internalDateMillis()))
            + "\n";
    out.write(from.getBytes(StandardCharsets.US_ASCII));
    boolean endsWithNewline = true;
    try (InputStream in = lease.openMessage(record)) {
      MboxrdQuoter quoter = new MboxrdQuoter(out);
      byte[] buffer = new byte[16 * 1024];
      int n;
      while ((n = in.read(buffer)) > 0) {
        quoter.write(buffer, n);
        endsWithNewline = buffer[n - 1] == '\n';
      }
      quoter.finish();
    }
    out.write(endsWithNewline ? new byte[] {'\n'} : new byte[] {'\n', '\n'});
  }

  private static void manifestEntry(StringBuilder manifest, long uid, MessageRecord record) {
    Flags flags = record.flags();
    manifest.append("{\"uid\":").append(uid).append(",\"flags\":[");
    String[] names = {"\\\\Seen", "\\\\Answered", "\\\\Flagged", "\\\\Deleted", "\\\\Draft"};
    int[] bits = {Flags.SEEN, Flags.ANSWERED, Flags.FLAGGED, Flags.DELETED, Flags.DRAFT};
    boolean first = true;
    for (int i = 0; i < bits.length; i++) {
      if ((flags.system() & bits[i]) != 0) {
        manifest.append(first ? "" : ",").append('"').append(names[i]).append('"');
        first = false;
      }
    }
    manifest.append("],\"keywords\":[");
    for (int i = 0; i < flags.keywords().size(); i++) {
      if (i > 0) {
        manifest.append(',');
      }
      quote(manifest, flags.keywords().get(i));
    }
    manifest
        .append("],\"internalDate\":\"")
        .append(Instant.ofEpochMilli(record.internalDateMillis()))
        .append("\"}");
  }

  /** Appends {@code value} as a JSON string literal. */
  static void quote(StringBuilder out, String value) {
    out.append('"');
    for (int i = 0; i < value.length(); i++) {
      char ch = value.charAt(i);
      switch (ch) {
        case '"' -> out.append("\\\"");
        case '\\' -> out.append("\\\\");
        case '\n' -> out.append("\\n");
        case '\r' -> out.append("\\r");
        case '\t' -> out.append("\\t");
        default -> {
          if (ch < 0x20) {
            out.append(String.format(Locale.ROOT, "\\u%04x", (int) ch));
          } else {
            out.append(ch);
          }
        }
      }
    }
    out.append('"');
  }

  /**
   * mboxrd quoting as a streaming state machine: a line matching {@code >*From } gains one more
   * {@code >}. Only the count of leading {@code >} and up to five bytes are held per line.
   */
  static final class MboxrdQuoter {
    private final OutputStream out;
    private boolean lineStart = true;
    private long quotes;
    private int matched;

    MboxrdQuoter(OutputStream out) {
      this.out = out;
    }

    void write(byte[] bytes, int length) throws IOException {
      int plainStart = 0;
      int i = 0;
      while (i < length) {
        byte b = bytes[i];
        if (!lineStart) {
          if (b == '\n') {
            lineStart = true;
            out.write(bytes, plainStart, i + 1 - plainStart);
            plainStart = i + 1;
          }
          i++;
        } else if (matched == 0 && b == '>') {
          // At the start of a line: hold back bytes while they can still form ">*From ".
          quotes++;
          plainStart = ++i;
        } else if (b == FROM[matched]) {
          matched++;
          plainStart = ++i;
          if (matched == FROM.length) {
            out.write('>');
            flushPending();
            lineStart = false;
          }
        } else {
          // Not a From line: release what was held and handle this byte in ordinary line mode.
          flushPending();
          lineStart = false;
          plainStart = i;
        }
      }
      if (!lineStart) {
        out.write(bytes, plainStart, length - plainStart);
      }
    }

    private void flushPending() throws IOException {
      for (long q = 0; q < quotes; q++) {
        out.write('>');
      }
      out.write(FROM, 0, matched);
      quotes = 0;
      matched = 0;
    }

    void finish() throws IOException {
      if (lineStart) {
        flushPending();
      }
    }
  }
}
