package org.shem.policy;

import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import org.apache.james.mime4j.MimeException;
import org.apache.james.mime4j.message.DefaultBodyDescriptorBuilder;
import org.apache.james.mime4j.message.MaximalBodyDescriptor;
import org.apache.james.mime4j.stream.BodyDescriptor;
import org.apache.james.mime4j.stream.EntityState;
import org.apache.james.mime4j.stream.MimeConfig;
import org.apache.james.mime4j.stream.MimeTokenStream;
import org.jspecify.annotations.Nullable;

/**
 * One bounded streaming pass over a message: decoded text of {@code text/*} parts (for rules) and
 * the names and types of attachments. Nothing is written anywhere; mime4j's token stream decodes in
 * memory and never uses a storage provider.
 */
final class MessageScan {
  static final int MAX_TEXT_CHARS = 1 << 20;
  static final int MAX_PARTS = 1000;

  /** A non-text or named part. */
  record Attachment(String fileName, String mimeType) {}

  record Result(
      String headerText, String bodyText, List<Attachment> attachments, boolean malformed) {}

  private MessageScan() {}

  static Result scan(InputStream message) throws IOException {
    StringBuilder headers = new StringBuilder();
    StringBuilder text = new StringBuilder();
    List<Attachment> attachments = new ArrayList<>();
    boolean malformed = false;
    MimeTokenStream parser =
        new MimeTokenStream(
            MimeConfig.custom()
                .setMaxLineLen(-1)
                .setMaxHeaderCount(HeaderBlock.MAX_FIELDS)
                .setMaxHeaderLen(64 * 1024)
                .build(),
            new DefaultBodyDescriptorBuilder());
    int parts = 0;
    try {
      parser.parse(message);
      for (EntityState state = parser.next();
          state != EntityState.T_END_OF_STREAM;
          state = parser.next()) {
        switch (state) {
          case T_START_BODYPART -> {
            if (++parts > MAX_PARTS) {
              return new Result(headers.toString(), text.toString(), attachments, true);
            }
          }
          case T_FIELD ->
              append(
                  headers, parser.getField().getName() + ": " + parser.getField().getBody() + "\n");
          case T_BODY -> {
            BodyDescriptor descriptor = parser.getBodyDescriptor();
            String name = fileName(descriptor);
            String type = descriptor.getMimeType().toLowerCase(Locale.ROOT);
            if (name != null || !type.startsWith("text/")) {
              attachments.add(new Attachment(name == null ? "" : name, type));
            }
            if (type.startsWith("text/") && text.length() < MAX_TEXT_CHARS) {
              try (Reader reader = parser.getReader()) {
                char[] buffer = new char[4096];
                int n;
                while ((n = reader.read(buffer)) > 0 && text.length() < MAX_TEXT_CHARS) {
                  text.append(buffer, 0, Math.min(n, MAX_TEXT_CHARS - text.length()));
                }
              }
              text.append('\n');
            }
          }
          default -> {}
        }
      }
    } catch (MimeException | RuntimeException e) {
      malformed = true;
    }
    return new Result(headers.toString(), text.toString(), attachments, malformed);
  }

  private static void append(StringBuilder target, String value) {
    if (target.length() + value.length() <= MAX_TEXT_CHARS) {
      target.append(value);
    }
  }

  private static @Nullable String fileName(BodyDescriptor descriptor) {
    if (descriptor instanceof MaximalBodyDescriptor maximal) {
      String disposition = maximal.getContentDispositionFilename();
      if (disposition != null && !disposition.isBlank()) {
        return disposition.trim();
      }
      String name = maximal.getContentTypeParameters().get("name");
      if (name != null && !name.isBlank()) {
        return name.trim();
      }
    }
    return null;
  }
}
