package org.shem.search;

import java.io.IOException;
import java.io.InputStream;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.james.mime4j.MimeException;
import org.apache.james.mime4j.stream.BodyDescriptor;
import org.apache.james.mime4j.stream.EntityState;
import org.apache.james.mime4j.stream.MimeConfig;
import org.apache.james.mime4j.stream.MimeTokenStream;
import org.apache.james.mime4j.stream.RecursionMode;
import org.jspecify.annotations.Nullable;

/**
 * Walks a message and hands each attachment's decoded bytes to a visitor (ADR 0019). An attachment
 * is a leaf part with {@code Content-Disposition: attachment}, or any leaf part that is not an
 * inline {@code text/plain} or {@code text/html} body (those are already covered by standard IMAP
 * search). Embedded {@code message/rfc822} parts are not descended into; they are attachments in
 * their own right and go to the mail parser whole.
 */
final class AttachmentParts {
  private static final Pattern FILENAME =
      Pattern.compile("(?i)(?:file)?name\\*?=\\s*\"?([^\";]*)\"?");
  private static final Pattern EXTENSION = Pattern.compile("[a-z0-9]{1,10}");

  private AttachmentParts() {}

  /** One attachment's declared type, file-name extension, and decoded content. */
  interface Visitor {
    /** Returns false to stop the walk. */
    boolean visit(String mimeType, @Nullable String extension, InputStream decoded)
        throws IOException, InterruptedException, AttachmentExtractor.UnavailableException;
  }

  /** Thrown when the message cannot be parsed; the caller must not claim coverage. */
  static final class MalformedException extends Exception {
    private static final long serialVersionUID = 1L;

    MalformedException(Throwable cause) {
      super("message not parseable", cause);
    }
  }

  static void walk(InputStream message, Visitor visitor)
      throws IOException,
          InterruptedException,
          MalformedException,
          AttachmentExtractor.UnavailableException {
    MimeTokenStream parser =
        new MimeTokenStream(MimeConfig.custom().setMaxLineLen(-1).setMaxHeaderLen(-1).build());
    parser.setRecursionMode(RecursionMode.M_NO_RECURSE);
    String disposition = null;
    try {
      parser.parse(message);
      for (EntityState state = parser.next();
          state != EntityState.T_END_OF_STREAM;
          state = parser.next()) {
        switch (state) {
          case T_START_HEADER -> disposition = null;
          case T_FIELD -> {
            if (parser.getField().getName().equalsIgnoreCase("Content-Disposition")) {
              disposition = parser.getField().getBody();
            }
          }
          case T_BODY -> {
            BodyDescriptor descriptor = parser.getBodyDescriptor();
            String type = descriptor.getMimeType().toLowerCase(Locale.ROOT);
            if (isAttachment(type, disposition)) {
              String extension = extension(disposition);
              try (InputStream decoded = parser.getDecodedInputStream()) {
                if (!visitor.visit(type, extension, decoded)) {
                  return;
                }
              }
            }
          }
          default -> {}
        }
      }
    } catch (MimeException | RuntimeException e) {
      throw new MalformedException(e);
    }
  }

  static boolean isAttachment(String mimeType, @Nullable String disposition) {
    boolean attachment =
        disposition != null
            && disposition.strip().toLowerCase(Locale.ROOT).startsWith("attachment");
    boolean body = mimeType.equals("text/plain") || mimeType.equals("text/html");
    return attachment || !body;
  }

  /** The lower-case file-name extension from a disposition, if it is short and alphanumeric. */
  static @Nullable String extension(@Nullable String disposition) {
    if (disposition == null) {
      return null;
    }
    Matcher matcher = FILENAME.matcher(disposition);
    if (!matcher.find()) {
      return null;
    }
    String name = matcher.group(1).strip();
    int dot = name.lastIndexOf('.');
    if (dot < 0 || dot == name.length() - 1) {
      return null;
    }
    String extension = name.substring(dot + 1).toLowerCase(Locale.ROOT);
    return EXTENSION.matcher(extension).matches() ? extension : null;
  }
}
