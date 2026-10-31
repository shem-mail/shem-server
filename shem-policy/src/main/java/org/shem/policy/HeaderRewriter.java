package org.shem.policy;

import java.io.ByteArrayOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.function.Predicate;

/**
 * Byte-exact header rewriting: prepends new fields and removes selected existing fields without
 * re-encoding anything else. {@link #plan} makes one pass to find the byte ranges to drop, so the
 * rewritten size is known before delivery; {@link Plan#apply} then streams the result.
 */
public final class HeaderRewriter {
  private HeaderRewriter() {}

  /** A byte range {@code [start, end)} of the original message. */
  record Range(long start, long end) {}

  /** The bytes to prepend and the original ranges to drop. */
  public static final class Plan {
    private final byte[] prefix;
    private final List<Range> drops;
    private final long originalSize;

    private Plan(byte[] prefix, List<Range> drops, long originalSize) {
      this.prefix = prefix;
      this.drops = List.copyOf(drops);
      this.originalSize = originalSize;
    }

    /** Size of the rewritten message. */
    public long size() {
      long dropped = 0;
      for (Range range : drops) {
        dropped += range.end() - range.start();
      }
      return prefix.length + originalSize - dropped;
    }

    /** Number of fields removed. */
    public int removed() {
      return drops.size();
    }

    /** Streams the rewritten message from a fresh stream of the original. */
    public InputStream apply(InputStream original) {
      return new Rewriting(prefix, drops, original);
    }
  }

  /**
   * Plans the rewrite. {@code drop} receives each top-level header field (name and value,
   * unfolded). Fields beyond {@link HeaderBlock#MAX_HEADER_BYTES} are left untouched.
   */
  public static Plan plan(
      InputStream original, long originalSize, List<String> prepend, Predicate<String> drop)
      throws IOException {
    ByteArrayOutputStream prefix = new ByteArrayOutputStream();
    for (String field : prepend) {
      prefix.writeBytes((field + "\r\n").getBytes(StandardCharsets.UTF_8));
    }
    List<Range> drops = new ArrayList<>();
    long position = 0;
    long fieldStart = -1;
    ByteArrayOutputStream field = new ByteArrayOutputStream();
    ByteArrayOutputStream line = new ByteArrayOutputStream();
    int b;
    while ((b = original.read()) != -1 && position < HeaderBlock.MAX_HEADER_BYTES) {
      position++;
      line.write(b);
      if (b != '\n') {
        continue;
      }
      byte[] bytes = line.toByteArray();
      long lineStart = position - bytes.length;
      line.reset();
      boolean blank = bytes.length <= 2 && (bytes[0] == '\r' || bytes[0] == '\n');
      boolean continuation = !blank && (bytes[0] == ' ' || bytes[0] == '\t');
      if (continuation && fieldStart >= 0) {
        field.write(bytes, 0, bytes.length);
        continue;
      }
      if (fieldStart >= 0 && drop.test(unfold(field))) {
        drops.add(new Range(fieldStart, lineStart));
      }
      field.reset();
      if (blank) {
        fieldStart = -1;
        break;
      }
      fieldStart = lineStart;
      field.write(bytes, 0, bytes.length);
    }
    return new Plan(prefix.toByteArray(), drops, originalSize);
  }

  private static String unfold(ByteArrayOutputStream field) {
    return field.toString(StandardCharsets.UTF_8).replace("\r\n", "").replace("\n", "").strip();
  }

  /** Whether {@code field} ({@code Name: value}) has the given name, case-insensitively. */
  public static boolean named(String field, String name) {
    int colon = field.indexOf(':');
    return colon > 0 && field.substring(0, colon).strip().toLowerCase(Locale.ROOT).equals(name);
  }

  private static final class Rewriting extends FilterInputStream {
    private final byte[] prefix;
    private final List<Range> drops;
    private int prefixRead;
    private long position;
    private int nextDrop;

    Rewriting(byte[] prefix, List<Range> drops, InputStream in) {
      super(in);
      this.prefix = prefix;
      this.drops = drops;
    }

    @Override
    public int read() throws IOException {
      byte[] one = new byte[1];
      int n = read(one, 0, 1);
      return n <= 0 ? -1 : one[0] & 0xff;
    }

    @Override
    public int read(byte[] buffer, int offset, int length) throws IOException {
      if (length == 0) {
        return 0;
      }
      if (prefixRead < prefix.length) {
        int n = Math.min(length, prefix.length - prefixRead);
        System.arraycopy(prefix, prefixRead, buffer, offset, n);
        prefixRead += n;
        return n;
      }
      while (nextDrop < drops.size() && position >= drops.get(nextDrop).start()) {
        long end = drops.get(nextDrop).end();
        while (position < end) {
          long skipped = in.skip(end - position);
          if (skipped <= 0) {
            if (in.read() == -1) {
              return -1;
            }
            skipped = 1;
          }
          position += skipped;
        }
        nextDrop++;
      }
      int limit = length;
      if (nextDrop < drops.size()) {
        limit = (int) Math.min(limit, drops.get(nextDrop).start() - position);
      }
      int n = in.read(buffer, offset, limit);
      if (n > 0) {
        position += n;
      }
      return n;
    }

    @Override
    public long skip(long n) throws IOException {
      byte[] discard = new byte[(int) Math.min(n, 8192)];
      long total = 0;
      while (total < n) {
        int r = read(discard, 0, (int) Math.min(discard.length, n - total));
        if (r <= 0) {
          break;
        }
        total += r;
      }
      return total;
    }

    @Override
    public int available() {
      return 0;
    }

    @Override
    public boolean markSupported() {
      return false;
    }
  }
}
