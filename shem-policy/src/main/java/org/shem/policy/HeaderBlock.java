package org.shem.policy;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import org.apache.james.jdkim.api.Headers;

/**
 * The raw header fields of a message, read up to a bound, leaving the stream at the start of the
 * body. Fields keep their original folding (without the final CRLF), as DKIM canonicalization
 * requires. At most {@link #MAX_DKIM_SIGNATURES} DKIM-Signature fields are exposed, bounding DNS
 * lookups and verification work per message.
 */
final class HeaderBlock implements Headers {
  static final int MAX_HEADER_BYTES = 256 * 1024;
  static final int MAX_FIELDS = 1000;
  static final int MAX_DKIM_SIGNATURES = 5;

  private final List<String> fields;
  private final boolean complete;

  private HeaderBlock(List<String> fields, boolean complete) {
    this.fields = List.copyOf(fields);
    this.complete = complete;
  }

  /**
   * Reads the header section. {@link #complete()} is false when the bound was hit or the stream
   * ended inside the headers.
   */
  static HeaderBlock read(InputStream in) throws IOException {
    List<String> fields = new ArrayList<>();
    ByteArrayOutputStream field = new ByteArrayOutputStream();
    ByteArrayOutputStream line = new ByteArrayOutputStream();
    int total = 0;
    int b;
    while ((b = in.read()) != -1) {
      if (++total > MAX_HEADER_BYTES) {
        return new HeaderBlock(fields, false);
      }
      if (b != '\n') {
        line.write(b);
        continue;
      }
      byte[] bytes = line.toByteArray();
      line.reset();
      int length =
          bytes.length > 0 && bytes[bytes.length - 1] == '\r' ? bytes.length - 1 : bytes.length;
      if (length == 0) {
        flush(field, fields);
        return new HeaderBlock(fields, fields.size() <= MAX_FIELDS);
      }
      if ((bytes[0] == ' ' || bytes[0] == '\t') && field.size() > 0) {
        field.write('\r');
        field.write('\n');
      } else {
        flush(field, fields);
      }
      field.write(bytes, 0, length);
      if (fields.size() > MAX_FIELDS) {
        return new HeaderBlock(fields, false);
      }
    }
    flush(field, fields);
    return new HeaderBlock(fields, false);
  }

  private static void flush(ByteArrayOutputStream field, List<String> fields) {
    if (field.size() > 0) {
      fields.add(field.toString(StandardCharsets.UTF_8));
      field.reset();
    }
  }

  boolean complete() {
    return complete;
  }

  @Override
  public List<String> getFields() {
    return limited(fields);
  }

  @Override
  public List<String> getFields(String name) {
    List<String> matching = new ArrayList<>();
    for (String field : fields) {
      if (name(field).equalsIgnoreCase(name)) {
        matching.add(field);
      }
    }
    return limited(matching);
  }

  /** Unfolded values of the fields named {@code name}. */
  List<String> values(String name) {
    List<String> values = new ArrayList<>();
    for (String field : getFields(name)) {
      int colon = field.indexOf(':');
      values.add(field.substring(colon + 1).replace("\r\n", "").trim());
    }
    return values;
  }

  private static List<String> limited(List<String> list) {
    List<String> result = new ArrayList<>();
    int signatures = 0;
    for (String field : list) {
      if (name(field).equalsIgnoreCase("DKIM-Signature") && ++signatures > MAX_DKIM_SIGNATURES) {
        continue;
      }
      result.add(field);
    }
    return result;
  }

  static String name(String field) {
    int colon = field.indexOf(':');
    return (colon < 0 ? field : field.substring(0, colon)).trim().toLowerCase(Locale.ROOT);
  }
}
