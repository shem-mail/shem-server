package org.shem.search;

import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.util.HashSet;
import java.util.Set;
import org.apache.james.mime4j.MimeException;
import org.apache.james.mime4j.stream.EntityState;
import org.apache.james.mime4j.stream.MimeConfig;
import org.apache.james.mime4j.stream.MimeTokenStream;
import org.jspecify.annotations.Nullable;

/**
 * Extracts the character trigrams of exactly the text James's exact evaluator scans for IMAP {@code
 * BODY} and {@code TEXT} (mime4j {@code MessageMatcher}): raw header field bodies, and every
 * decoded body, preamble, and epilogue, compared after per-character {@link
 * Character#toUpperCase(char)}. Any substring a search can match lies inside one such segment, so
 * all its trigrams are in the extracted set; the index therefore never produces false negatives.
 */
final class SearchText {
  static final int GRAM = 3;
  static final int MAX_TRIGRAMS = 300_000;

  private SearchText() {}

  /** Trigrams of headers and bodies. */
  record Grams(Set<String> body, Set<String> text) {}

  /**
   * Returns the trigram sets, or {@code null} when the message cannot be indexed completely (parse
   * failure, unsupported charset, or too many distinct trigrams); such messages stay uncovered and
   * are always evaluated exactly.
   */
  static @Nullable Grams extract(InputStream message) throws IOException {
    // James's matcher keeps its partial-match state across fields and parts, so a match may span
    // a segment boundary; trigrams are therefore taken over each continuous stream it reads.
    Stream body = new Stream();
    Stream text = new Stream();
    try {
      MimeTokenStream parser =
          new MimeTokenStream(MimeConfig.custom().setMaxLineLen(-1).setMaxHeaderLen(-1).build());
      parser.parse(message);
      for (EntityState state = parser.next();
          state != EntityState.T_END_OF_STREAM;
          state = parser.next()) {
        switch (state) {
          case T_FIELD -> {
            if (!text.add(new java.io.StringReader(parser.getField().getBody()))) {
              return null;
            }
          }
          case T_PREAMBLE, T_EPILOGUE, T_BODY -> {
            StringBuilder decoded = new StringBuilder();
            try (Reader reader = parser.getReader()) {
              char[] buffer = new char[4096];
              int n;
              while ((n = reader.read(buffer)) > 0) {
                decoded.append(buffer, 0, n);
                if (decoded.length() > MAX_SEGMENT_CHARS) {
                  return null;
                }
              }
            }
            if (!body.add(new java.io.StringReader(decoded.toString()))
                || !text.add(new java.io.StringReader(decoded.toString()))) {
              return null;
            }
          }
          default -> {}
        }
      }
    } catch (MimeException | RuntimeException e) {
      // Same inputs make James's matcher give up; never claim coverage for them.
      return null;
    }
    return new Grams(body.grams, text.grams);
  }

  static final int MAX_SEGMENT_CHARS = 64 * 1024 * 1024;

  /** Sliding trigram window over one continuous character stream. */
  private static final class Stream {
    final Set<String> grams = new HashSet<>();
    private final char[] window = new char[GRAM];
    private int filled;

    /** Adds the trigrams of the next chunk of the stream; false if the bound was exceeded. */
    boolean add(Reader reader) throws IOException {
      int read;
      while ((read = reader.read()) != -1) {
        char c = Character.toUpperCase((char) read);
        if (filled < GRAM) {
          window[filled++] = c;
        } else {
          window[0] = window[1];
          window[1] = window[2];
          window[2] = c;
        }
        if (filled == GRAM) {
          grams.add(new String(window));
          if (grams.size() > MAX_TRIGRAMS) {
            return false;
          }
        }
      }
      return true;
    }
  }

  /** Trigrams of a search value under the same normalization; empty for values shorter than 3. */
  static Set<String> queryGrams(String value) {
    Set<String> grams = new java.util.LinkedHashSet<>();
    char[] upper = new char[value.length()];
    for (int i = 0; i < upper.length; i++) {
      upper[i] = Character.toUpperCase(value.charAt(i));
    }
    for (int i = 0; i + GRAM <= upper.length; i++) {
      grams.add(new String(upper, i, GRAM));
    }
    return grams;
  }
}
