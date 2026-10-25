package org.shem.imap;

import jakarta.mail.Flags.Flag;
import java.io.ByteArrayInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.apache.james.mailbox.MessageUid;
import org.apache.james.mailbox.ModSeq;
import org.apache.james.mailbox.exception.MailboxException;
import org.apache.james.mailbox.model.Content;
import org.apache.james.mailbox.model.MailboxId;
import org.apache.james.mailbox.model.ThreadId;
import org.apache.james.mailbox.store.mail.model.MailboxMessage;
import org.apache.james.mailbox.store.mail.model.impl.PropertyBuilder;
import org.apache.james.mailbox.store.mail.model.impl.SimpleMailboxMessage;
import org.apache.james.mime4j.dom.field.ContentDispositionField;
import org.apache.james.mime4j.dom.field.ContentTypeField;
import org.apache.james.mime4j.field.LenientFieldParser;
import org.apache.james.mime4j.stream.Field;
import org.apache.james.mime4j.stream.MimeConfig;
import org.apache.james.mime4j.stream.MimeTokenStream;
import org.jspecify.annotations.Nullable;
import org.shem.common.FormatException;
import org.shem.mailbox.MailboxLease;
import org.shem.mailbox.MessageSummary;
import org.shem.store.StorageException;
import org.shem.store.metadata.Flags;
import org.shem.store.metadata.MessageRecord;

/** Converts Shem metadata records into James message models with lazily decrypted content. */
@SuppressWarnings("JavaUtilDate") // the James mailbox API uses java.util.Date
final class MessageViews {
  private MessageViews() {}

  /** Records the first content failure so callers can fail instead of returning partial results. */
  static final class FailureTracker {
    private final AtomicReference<@Nullable IOException> failure = new AtomicReference<>();

    void record(IOException e) {
      failure.compareAndSet(null, e);
    }

    void throwIfFailed() throws MailboxException {
      IOException e = failure.get();
      if (e != null) {
        throw new MailboxException("message content could not be read", e);
      }
    }
  }

  static MailboxMessage message(
      MailboxLease lease,
      MailboxId mailboxId,
      long uid,
      MessageRecord record,
      @Nullable FailureTracker tracker)
      throws MailboxException {
    MessageSummary summary;
    try {
      summary = MessageSummary.decode(record.summary());
    } catch (FormatException e) {
      throw new MailboxException("message summary corrupt", e);
    }
    Ids.BlobId messageId = new Ids.BlobId(record.blobId());
    return SimpleMailboxMessage.builder()
        .messageId(messageId)
        .threadId(ThreadId.fromBaseMessageId(messageId))
        .uid(MessageUid.of(uid))
        .modseq(ModSeq.of(record.modSeq()))
        .internalDate(new Date(record.internalDateMillis()))
        .size(record.size())
        .bodyStartOctet((int) Math.min(Integer.MAX_VALUE, summary.bodyOffset()))
        .content(new LazyContent(lease, record, tracker))
        .flags(toJames(record.flags()))
        .properties(properties(summary))
        .mailboxId(mailboxId)
        .build();
  }

  /**
   * Root-entity MIME properties derived from the stored header section (as James computes them).
   */
  static PropertyBuilder properties(MessageSummary summary) {
    PropertyBuilder builder = new PropertyBuilder();
    String mediaType = "text";
    String subType = "plain";
    Map<String, String> parameters = new HashMap<>();
    for (Field raw : headerFields(summary)) {
      String name = raw.getName().toLowerCase(Locale.ROOT);
      switch (name) {
        case "content-type" -> {
          ContentTypeField type =
              (ContentTypeField) LenientFieldParser.getParser().parse(raw, null);
          if (type.getMimeType() != null && type.getMediaType() != null) {
            mediaType = type.getMediaType();
            subType = type.getSubType();
            parameters.putAll(type.getParameters());
          }
        }
        case "content-id" -> builder.setContentID(raw.getBody().trim());
        case "content-description" -> builder.setContentDescription(raw.getBody().trim());
        case "content-transfer-encoding" ->
            builder.setContentTransferEncoding(raw.getBody().trim().toLowerCase(Locale.ROOT));
        case "content-location" -> builder.setContentLocation(raw.getBody().trim());
        case "content-md5" -> builder.setContentMD5(raw.getBody().trim());
        case "content-language" ->
            builder.setContentLanguage(
                java.util.Arrays.stream(raw.getBody().split(","))
                    .map(String::trim)
                    .filter(s -> !s.isEmpty())
                    .toList());
        case "content-disposition" -> {
          ContentDispositionField disposition =
              (ContentDispositionField) LenientFieldParser.getParser().parse(raw, null);
          if (disposition.getDispositionType() != null) {
            builder.setContentDispositionType(disposition.getDispositionType());
            builder.setContentDispositionParameters(disposition.getParameters());
          }
        }
        default -> {}
      }
    }
    builder.setMediaType(mediaType);
    builder.setSubType(subType);
    String charset = parameters.get("charset");
    if (charset != null) {
      builder.setCharset(charset);
    }
    builder.setContentTypeParameters(parameters);
    if (mediaType.equalsIgnoreCase("text")) {
      builder.setTextualLineCount(summary.bodyLines());
    }
    return builder;
  }

  private static List<Field> headerFields(MessageSummary summary) {
    List<Field> fields = new java.util.ArrayList<>();
    MimeTokenStream stream = new MimeTokenStream(MimeConfig.PERMISSIVE);
    stream.parse(new ByteArrayInputStream(summary.headerSection().toByteArray()));
    try {
      for (org.apache.james.mime4j.stream.EntityState state = stream.getState();
          state != org.apache.james.mime4j.stream.EntityState.T_END_HEADER
              && state != org.apache.james.mime4j.stream.EntityState.T_END_OF_STREAM;
          state = stream.next()) {
        if (state == org.apache.james.mime4j.stream.EntityState.T_FIELD) {
          fields.add(stream.getField());
        }
      }
    } catch (IOException | org.apache.james.mime4j.MimeException e) {
      // Malformed headers: keep the fields parsed so far, as James's permissive parser would.
    }
    return fields;
  }

  static jakarta.mail.Flags toJames(Flags flags) {
    jakarta.mail.Flags result = new jakarta.mail.Flags();
    if (flags.has(Flags.SEEN)) {
      result.add(Flag.SEEN);
    }
    if (flags.has(Flags.ANSWERED)) {
      result.add(Flag.ANSWERED);
    }
    if (flags.has(Flags.FLAGGED)) {
      result.add(Flag.FLAGGED);
    }
    if (flags.has(Flags.DELETED)) {
      result.add(Flag.DELETED);
    }
    if (flags.has(Flags.DRAFT)) {
      result.add(Flag.DRAFT);
    }
    flags.keywords().forEach(result::add);
    return result;
  }

  /** Converts James flags; \Recent is session state in IMAP and is never persisted. */
  static Flags fromJames(jakarta.mail.Flags flags) {
    int system = 0;
    if (flags.contains(Flag.SEEN)) {
      system |= Flags.SEEN;
    }
    if (flags.contains(Flag.ANSWERED)) {
      system |= Flags.ANSWERED;
    }
    if (flags.contains(Flag.FLAGGED)) {
      system |= Flags.FLAGGED;
    }
    if (flags.contains(Flag.DELETED)) {
      system |= Flags.DELETED;
    }
    if (flags.contains(Flag.DRAFT)) {
      system |= Flags.DRAFT;
    }
    return new Flags(system, List.of(flags.getUserFlags()));
  }

  /** Decrypts on every read; nothing is cached. */
  private static final class LazyContent implements Content {
    private final MailboxLease lease;
    private final MessageRecord record;
    private final @Nullable FailureTracker tracker;

    LazyContent(MailboxLease lease, MessageRecord record, @Nullable FailureTracker tracker) {
      this.lease = lease;
      this.record = record;
      this.tracker = tracker;
    }

    @Override
    public InputStream getInputStream() throws IOException {
      try {
        InputStream in = lease.openMessage(record);
        return tracker == null ? in : new TrackingStream(in, tracker);
      } catch (StorageException e) {
        IOException failure = new IOException("message unavailable: " + e.kind(), e);
        if (tracker != null) {
          tracker.record(failure);
        }
        throw failure;
      }
    }

    @Override
    public long size() {
      return record.size();
    }
  }

  private static final class TrackingStream extends FilterInputStream {
    private final FailureTracker tracker;

    TrackingStream(InputStream in, FailureTracker tracker) {
      super(in);
      this.tracker = tracker;
    }

    @Override
    public int read() throws IOException {
      try {
        return super.read();
      } catch (IOException e) {
        tracker.record(e);
        throw e;
      }
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
      try {
        return super.read(b, off, len);
      } catch (IOException e) {
        tracker.record(e);
        throw e;
      }
    }
  }
}
