package org.shem.imap;

import jakarta.mail.Flags.Flag;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Date;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import org.apache.james.mailbox.MailboxSession;
import org.apache.james.mailbox.MessageManager;
import org.apache.james.mailbox.MessageUid;
import org.apache.james.mailbox.ModSeq;
import org.apache.james.mailbox.exception.MailboxException;
import org.apache.james.mailbox.exception.MailboxNotFoundException;
import org.apache.james.mailbox.exception.OverQuotaException;
import org.apache.james.mailbox.exception.UnsupportedRightException;
import org.apache.james.mailbox.model.ComposedMessageId;
import org.apache.james.mailbox.model.ComposedMessageIdWithMetaData;
import org.apache.james.mailbox.model.FetchGroup;
import org.apache.james.mailbox.model.Mailbox;
import org.apache.james.mailbox.model.MailboxACL;
import org.apache.james.mailbox.model.MailboxCounters;
import org.apache.james.mailbox.model.MailboxId;
import org.apache.james.mailbox.model.MailboxPath;
import org.apache.james.mailbox.model.MessageRange;
import org.apache.james.mailbox.model.MessageResult;
import org.apache.james.mailbox.model.MessageResultIterator;
import org.apache.james.mailbox.model.SearchQuery;
import org.apache.james.mailbox.model.ThreadId;
import org.apache.james.mailbox.model.UidValidity;
import org.apache.james.mailbox.store.MessageResultImpl;
import org.apache.james.mailbox.store.extractor.DefaultTextExtractor;
import org.apache.james.mailbox.store.mail.model.MailboxMessage;
import org.apache.james.mailbox.store.search.MessageSearchIndex;
import org.apache.james.mailbox.store.search.MessageSearches;
import org.jspecify.annotations.Nullable;
import org.reactivestreams.Publisher;
import org.shem.common.OpaqueId;
import org.shem.mailbox.MailboxLease;
import org.shem.search.SearchIndex;
import org.shem.store.StorageException;
import org.shem.store.metadata.Flags;
import org.shem.store.metadata.Folder;
import org.shem.store.metadata.MessageKey;
import org.shem.store.metadata.MessageRecord;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * One folder of an unlocked mailbox, seen through the James message-manager contract. Every call
 * reads current metadata through the session's lease; nothing is cached across calls.
 */
@SuppressWarnings("JavaUtilDate") // the James mailbox API uses java.util.Date
final class ShemMessageManager implements MessageManager {
  private final MailboxLease lease;
  private final OpaqueId folderId;
  private final MailboxPath path;
  private final UidValidity uidValidity;

  ShemMessageManager(MailboxLease lease, Folder folder, MailboxPath path) {
    this.lease = lease;
    this.folderId = folder.folderId();
    this.path = path;
    this.uidValidity = UidValidity.of(folder.uidValidity());
  }

  private Folder folder() throws MailboxException {
    return read(view -> view.folder(folderId))
        .orElseThrow(() -> new MailboxNotFoundException(path));
  }

  @Override
  public long getMessageCount(MailboxSession session) throws MailboxException {
    return read(view -> (long) view.uids(folderId).length);
  }

  @Override
  public MailboxCounters getMailboxCounters(MailboxSession session) throws MailboxException {
    long[] counts = new long[2];
    read(
        view -> {
          view.forEachMessage(
              folderId,
              (uid, record) -> {
                counts[0]++;
                if (!record.flags().has(Flags.SEEN)) {
                  counts[1]++;
                }
                return true;
              });
          return null;
        });
    return MailboxCounters.builder().mailboxId(getId()).count(counts[0]).unseen(counts[1]).build();
  }

  @Override
  public Publisher<MailboxCounters> getMailboxCountersReactive(MailboxSession session) {
    return blocking(() -> getMailboxCounters(session));
  }

  @Override
  @SuppressWarnings("deprecation") // still part of the James interface
  public boolean isWriteable(MailboxSession session) {
    return true;
  }

  @Override
  public Publisher<MessageUid> search(SearchQuery query, MailboxSession session)
      throws MailboxException {
    MessageViews.FailureTracker tracker = new MessageViews.FailureTracker();
    List<MailboxMessage> candidates = candidates(query, tracker);
    List<MessageUid> result = new ArrayList<>();
    for (MessageSearchIndex.SearchResult hit :
        new MessageSearches(
            candidates.iterator(),
            query,
            new DefaultTextExtractor(),
            (attachment, s) -> {
              throw new IOException("attachment search is not supported");
            },
            session)) {
      result.add(hit.getMessageUid());
    }
    // James's evaluator skips messages it cannot read; Shem refuses incomplete results instead.
    tracker.throwIfFailed();
    return Flux.fromIterable(result);
  }

  /**
   * Messages that may match: all of them, minus messages the committed index covers and that cannot
   * contain a required top-level BODY/TEXT value. Every remaining message is evaluated exactly, so
   * index lag or gaps can only cost time, never results.
   */
  private List<MailboxMessage> candidates(SearchQuery query, MessageViews.FailureTracker tracker)
      throws MailboxException {
    List<MailboxMessage> all = messages(MessageRange.all(), tracker);
    Optional<SearchIndex> index = lease.extension(SearchIndex.class);
    if (index.isEmpty()) {
      return all;
    }
    SearchIndex.Snapshot snapshot = index.get().acquire();
    try {
      Set<OpaqueId> allowed = null;
      for (SearchQuery.Criterion criterion : query.getCriteria()) {
        if (criterion instanceof SearchQuery.TextCriterion text
            && (text.getType() == SearchQuery.Scope.BODY
                || text.getType() == SearchQuery.Scope.FULL)) {
          Optional<Set<OpaqueId>> hits =
              index
                  .get()
                  .candidates(
                      snapshot,
                      text.getOperator().getValue(),
                      text.getType() == SearchQuery.Scope.FULL);
          if (hits.isPresent()) {
            if (allowed == null) {
              allowed = new HashSet<>(hits.get());
            } else {
              allowed.retainAll(hits.get());
            }
          }
        }
      }
      if (allowed == null) {
        return all;
      }
      List<MailboxMessage> filtered = new ArrayList<>();
      for (MailboxMessage message : all) {
        OpaqueId blob = ((Ids.BlobId) message.getMessageId()).id();
        if (!snapshot.covers(blob) || allowed.contains(blob)) {
          filtered.add(message);
        }
      }
      return filtered;
    } catch (IOException e) {
      // A failing index is derived data: fall back to evaluating everything exactly.
      return all;
    } finally {
      index.get().release(snapshot);
    }
  }

  @Override
  public Iterator<MessageUid> expunge(MessageRange set, MailboxSession session)
      throws MailboxException {
    List<MessageUid> removed = new ArrayList<>();
    write(
        session,
        tx -> {
          for (long uid : selected(tx.uids(folderId), set)) {
            MessageKey key = new MessageKey(folderId, uid);
            Optional<MessageRecord> record = tx.message(key);
            if (record.isPresent() && record.get().flags().has(Flags.DELETED)) {
              tx.remove(key);
              removed.add(MessageUid.of(uid));
            }
          }
          return null;
        });
    return removed.iterator();
  }

  @Override
  public void delete(List<MessageUid> uids, MailboxSession session) throws MailboxException {
    write(
        session,
        tx -> {
          for (MessageUid uid : uids) {
            MessageKey key = new MessageKey(folderId, uid.asLong());
            if (tx.message(key).isPresent()) {
              tx.remove(key);
            }
          }
          return null;
        });
  }

  @Override
  public Map<MessageUid, jakarta.mail.Flags> setFlags(
      jakarta.mail.Flags flags, FlagsUpdateMode mode, MessageRange set, MailboxSession session)
      throws MailboxException {
    Flags change = MessageViews.fromJames(flags);
    Map<MessageUid, jakarta.mail.Flags> result = new LinkedHashMap<>();
    write(
        session,
        tx -> {
          for (long uid : selected(tx.uids(folderId), set)) {
            MessageKey key = new MessageKey(folderId, uid);
            MessageRecord record = tx.message(key).orElseThrow();
            Flags next =
                switch (mode) {
                  case ADD -> record.flags().plus(change);
                  case REMOVE -> record.flags().minus(change);
                  case REPLACE -> change;
                };
            if (!next.equals(record.flags())) {
              tx.setFlags(key, next);
            }
            result.put(MessageUid.of(uid), MessageViews.toJames(next));
          }
          return null;
        });
    return result;
  }

  @Override
  public AppendResult appendMessage(
      InputStream message,
      Date internalDate,
      MailboxSession session,
      boolean isRecent,
      jakarta.mail.Flags flags)
      throws MailboxException {
    MailboxLease l = Sessions.lease(session);
    long uid;
    try {
      uid =
          l.append(
              session.getSessionId(),
              folderId,
              message,
              MessageViews.fromJames(flags == null ? new jakarta.mail.Flags() : flags),
              (internalDate == null ? new Date() : internalDate).getTime());
    } catch (StorageException e) {
      if (e.kind() == StorageException.Kind.LIMIT_EXCEEDED) {
        throw new OverQuotaException("message rejected by size or quota limit", null, null);
      }
      throw storage(e);
    }
    MessageRecord record =
        read(view -> view.message(new MessageKey(folderId, uid)))
            .orElseThrow(() -> new MailboxException("appended message vanished"));
    Ids.BlobId messageId = new Ids.BlobId(record.blobId());
    return new AppendResult(
        new ComposedMessageId(getId(), messageId, MessageUid.of(uid)),
        record.size(),
        Optional.empty(),
        ThreadId.fromBaseMessageId(messageId));
  }

  @Override
  public AppendResult appendMessage(AppendCommand command, MailboxSession session)
      throws MailboxException {
    try (InputStream in = command.getMsgIn().getInputStream()) {
      return appendMessage(
          in, command.getInternalDate(), session, command.isRecent(), command.getFlags());
    } catch (IOException e) {
      throw new MailboxException("message content unreadable", e);
    }
  }

  @Override
  public Publisher<AppendResult> appendMessageReactive(
      AppendCommand command, MailboxSession session) {
    return blocking(() -> appendMessage(command, session));
  }

  @Override
  public MessageResultIterator getMessages(
      MessageRange set, FetchGroup group, MailboxSession session) throws MailboxException {
    Iterator<MailboxMessage> messages = messages(set, null).iterator();
    return new MessageResultIterator() {
      @Override
      public boolean hasNext() {
        return messages.hasNext();
      }

      @Override
      public MessageResult next() {
        return new MessageResultImpl(messages.next());
      }

      @Override
      public @Nullable MailboxException getException() {
        return null;
      }
    };
  }

  @Override
  public Publisher<ComposedMessageIdWithMetaData> listMessagesMetadata(
      MessageRange set, MailboxSession session) {
    return blocking(
            () -> {
              List<ComposedMessageIdWithMetaData> result = new ArrayList<>();
              read(
                  view -> {
                    view.forEachMessage(
                        folderId,
                        (uid, record) -> {
                          if (set.includes(MessageUid.of(uid))) {
                            Ids.BlobId messageId = new Ids.BlobId(record.blobId());
                            result.add(
                                ComposedMessageIdWithMetaData.builder()
                                    .composedMessageId(
                                        new ComposedMessageId(
                                            getId(), messageId, MessageUid.of(uid)))
                                    .flags(MessageViews.toJames(record.flags()))
                                    .modSeq(ModSeq.of(record.modSeq()))
                                    .threadId(ThreadId.fromBaseMessageId(messageId))
                                    .build());
                          }
                          return true;
                        });
                    return null;
                  });
              return result;
            })
        .flatMapMany(Flux::fromIterable);
  }

  @Override
  public Mailbox getMailboxEntity() {
    return new Mailbox(path, uidValidity, getId());
  }

  @Override
  public MailboxId getId() {
    return new Ids.FolderId(folderId);
  }

  @Override
  public MailboxPath getMailboxPath() {
    return path;
  }

  @Override
  public jakarta.mail.Flags getApplicableFlags(MailboxSession session) throws MailboxException {
    jakarta.mail.Flags flags = permanentSystemFlags();
    TreeSet<String> keywords = new TreeSet<>();
    read(
        view -> {
          view.forEachMessage(
              folderId,
              (uid, record) -> {
                keywords.addAll(record.flags().keywords());
                return true;
              });
          return null;
        });
    keywords.forEach(flags::add);
    return flags;
  }

  @Override
  public MailboxMetaData getMetaData(
      MailboxMetaData.RecentMode recentMode,
      MailboxSession session,
      EnumSet<MailboxMetaData.Item> items)
      throws MailboxException {
    Folder folder = folder();
    long[] counts = new long[2];
    long[] firstUnseen = new long[1];
    long highest =
        read(
            view -> {
              view.forEachMessage(
                  folderId,
                  (uid, record) -> {
                    counts[0]++;
                    if (!record.flags().has(Flags.SEEN)) {
                      counts[1]++;
                      if (firstUnseen[0] == 0) {
                        firstUnseen[0] = uid;
                      }
                    }
                    return true;
                  });
              return view.highestModSeq();
            });
    return new MailboxMetaData(
        List.of(),
        getPermanentFlags(session),
        uidValidity,
        MessageUid.of(folder.uidNext()),
        ModSeq.of(Math.max(1, highest)),
        counts[0],
        counts[1],
        firstUnseen[0] == 0 ? null : MessageUid.of(firstUnseen[0]),
        true,
        MailboxACL.OWNER_FULL_ACL);
  }

  @Override
  public jakarta.mail.Flags getPermanentFlags(MailboxSession session) {
    jakarta.mail.Flags flags = permanentSystemFlags();
    flags.add(Flag.USER);
    return flags;
  }

  private static jakarta.mail.Flags permanentSystemFlags() {
    jakarta.mail.Flags flags = new jakarta.mail.Flags();
    flags.add(Flag.ANSWERED);
    flags.add(Flag.DELETED);
    flags.add(Flag.DRAFT);
    flags.add(Flag.FLAGGED);
    flags.add(Flag.SEEN);
    return flags;
  }

  @Override
  public MailboxACL getResolvedAcl(MailboxSession session) throws UnsupportedRightException {
    return MailboxACL.OWNER_FULL_ACL;
  }

  // ---- helpers ----

  /** Messages in {@code set}, in UID order, as James models with lazily decrypted content. */
  List<MailboxMessage> messages(MessageRange set, MessageViews.@Nullable FailureTracker tracker)
      throws MailboxException {
    List<long[]> uids = new ArrayList<>();
    List<MessageRecord> records = new ArrayList<>();
    read(
        view -> {
          view.forEachMessage(
              folderId,
              (uid, record) -> {
                if (set.includes(MessageUid.of(uid))) {
                  uids.add(new long[] {uid});
                  records.add(record);
                }
                return true;
              });
          return null;
        });
    List<MailboxMessage> result = new ArrayList<>(records.size());
    MailboxId id = getId();
    for (int i = 0; i < records.size(); i++) {
      result.add(MessageViews.message(lease, id, uids.get(i)[0], records.get(i), tracker));
    }
    return result;
  }

  static List<Long> selected(long[] uids, MessageRange set) {
    List<Long> result = new ArrayList<>();
    for (long uid : uids) {
      if (set.includes(MessageUid.of(uid))) {
        result.add(uid);
      }
    }
    return result;
  }

  OpaqueId folderId() {
    return folderId;
  }

  private <T extends @Nullable Object> T read(
      org.shem.store.metadata.MetadataStore.ReadBody<T> body) throws MailboxException {
    try {
      return lease.read(body);
    } catch (StorageException e) {
      throw storage(e);
    } catch (org.shem.mailbox.RevokedLeaseException e) {
      throw new MailboxException("session no longer authorized", e);
    }
  }

  private <T extends @Nullable Object> T write(
      MailboxSession session, org.shem.store.metadata.MetadataStore.TxBody<T> body)
      throws MailboxException {
    try {
      return Sessions.lease(session).write(session.getSessionId(), body);
    } catch (StorageException e) {
      throw storage(e);
    } catch (org.shem.mailbox.RevokedLeaseException e) {
      throw new MailboxException("session no longer authorized", e);
    }
  }

  static MailboxException storage(StorageException e) {
    return switch (e.kind()) {
      case NOT_FOUND -> new MailboxNotFoundException("not found");
      default -> new MailboxException("storage failure: " + e.kind(), e);
    };
  }

  /** Runs blocking store work off the protocol event loop. */
  static <T> Mono<T> blocking(Callable<T> callable) {
    return Mono.fromCallable(callable::call).subscribeOn(Schedulers.boundedElastic());
  }

  /** Callable that may throw mailbox exceptions. */
  @FunctionalInterface
  interface Callable<T> {
    T call() throws MailboxException;
  }
}
