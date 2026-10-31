package org.shem.mailbox;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import org.shem.common.FormatException;
import org.shem.common.ImmutableBytes;
import org.shem.common.RecordReader;
import org.shem.common.RecordWriter;

/**
 * Precomputed per-message summary stored (encrypted) in metadata so that listing, ENVELOPE, and
 * header searches do not need to decrypt the blob: the raw header section (bounded), the body
 * offset, and the body line count.
 *
 * @param headerSection raw header bytes including the terminating blank line; truncated at {@link
 *     #MAX_HEADER_BYTES} with {@code headerTruncated} set
 */
public record MessageSummary(
    ImmutableBytes headerSection, boolean headerTruncated, long bodyOffset, long bodyLines) {
  public static final int MAX_HEADER_BYTES = 128 * 1024;
  private static final int FORMAT = 1;

  public ImmutableBytes encode() {
    return ImmutableBytes.copyOf(
        new RecordWriter()
            .u8(FORMAT)
            .bytes(headerSection.toByteArray())
            .bool(headerTruncated)
            .i64(bodyOffset)
            .i64(bodyLines)
            .toByteArray());
  }

  public static MessageSummary decode(ImmutableBytes encoded) throws FormatException {
    RecordReader in = new RecordReader(encoded.toByteArray());
    if (in.u8() != FORMAT) {
      throw new FormatException("unknown summary format");
    }
    MessageSummary summary =
        new MessageSummary(
            ImmutableBytes.copyOf(in.bytes(MAX_HEADER_BYTES)), in.bool(), in.i64(), in.i64());
    in.expectEnd();
    return summary;
  }

  /** Scans a message once, keeping only the header section in memory. */
  public static MessageSummary compute(InputStream message) throws IOException {
    byte[] header = new byte[4096];
    int headerLength = 0;
    boolean truncated = false;
    long offset = 0;
    int state = 0; // progress through "\r\n\r\n" or "\n\n"
    boolean inBody = false;
    long lines = 0;
    boolean lineHasContent = false;
    byte[] buffer = new byte[16 * 1024];
    int n;
    while ((n = message.read(buffer)) > 0) {
      for (int i = 0; i < n; i++) {
        byte b = buffer[i];
        if (!inBody) {
          offset++;
          if (headerLength < MAX_HEADER_BYTES) {
            if (headerLength == header.length) {
              header = Arrays.copyOf(header, Math.min(header.length * 2, MAX_HEADER_BYTES));
            }
            header[headerLength++] = b;
          } else {
            truncated = true;
          }
          state = advance(state, b);
          if (state == 4) {
            inBody = true;
          }
        } else if (b == '\n') {
          lines++;
          lineHasContent = false;
        } else {
          lineHasContent = true;
        }
      }
    }
    Arrays.fill(buffer, (byte) 0);
    if (lineHasContent) {
      lines++;
    }
    if (!inBody) {
      // No blank line: the whole message is header; IMAP treats the body as empty.
      offset = headerLength;
    }
    ImmutableBytes headerBytes = ImmutableBytes.copyOf(Arrays.copyOf(header, headerLength));
    Arrays.fill(header, (byte) 0);
    return new MessageSummary(headerBytes, truncated, offset, lines);
  }

  private static int advance(int state, byte b) {
    // Accept CRLF CRLF, and bare LF LF for non-canonical input.
    if (b == '\n') {
      return state == 1 || state == 3 ? state + 1 : (state == 2 ? 4 : 2);
    }
    if (b == '\r') {
      return state == 2 ? 3 : 1;
    }
    return 0;
  }
}
