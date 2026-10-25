package org.shem.imap;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.WeakHashMap;
import org.apache.james.core.Username;
import org.apache.james.core.quota.QuotaCountUsage;
import org.apache.james.core.quota.QuotaSizeUsage;
import org.apache.james.events.Event;
import org.apache.james.events.EventBus;
import org.apache.james.mailbox.MailboxSession;
import org.apache.james.mailbox.MessageUid;
import org.apache.james.mailbox.ModSeq;
import org.apache.james.mailbox.events.MailboxEvents;
import org.apache.james.mailbox.events.MailboxIdRegistrationKey;
import org.apache.james.mailbox.model.MailboxACL;
import org.apache.james.mailbox.model.MailboxConstants;
import org.apache.james.mailbox.model.MailboxPath;
import org.apache.james.mailbox.model.MessageMetaData;
import org.apache.james.mailbox.model.QuotaRoot;
import org.apache.james.mailbox.model.ThreadId;
import org.apache.james.mailbox.model.UpdatedFlags;
import org.jspecify.annotations.Nullable;
import org.shem.common.OpaqueId;
import org.shem.mailbox.MailboxLease;
import org.shem.store.StorageException;
import org.shem.store.metadata.Folder;
import org.shem.store.metadata.MessageRecord;
import org.shem.store.metadata.MetadataChange;

/**
 * Translates committed metadata changes from any writer (this or another IMAP session, receipt
 * import, HTTP) into in-memory James mailbox events, which drive selected-mailbox state and IDLE.
 * One registration per unlocked mailbox; it ends when the mailbox coordinator closes.
 */
@SuppressWarnings("JavaUtilDate") // the James event API uses java.util.Date
final class EventPublisher {
  private static final MailboxSession.SessionId SYSTEM = MailboxSession.SessionId.of(0);
  private final EventBus eventBus;
  private final Map<Object, Boolean> registered = new WeakHashMap<>();

  EventPublisher(EventBus eventBus) {
    this.eventBus = eventBus;
  }

  /** Ensures changes of the lease's mailbox are published; idempotent per coordinator. */
  void attach(MailboxLease lease, Username user) throws StorageException {
    Object token = lease.coordinatorToken();
    synchronized (registered) {
      if (registered.containsKey(token)) {
        return;
      }
      Map<OpaqueId, String> names = new HashMap<>();
      lease.read(
          view -> {
            for (Folder folder : view.folders()) {
              names.put(folder.folderId(), folder.name());
            }
            return null;
          });
      lease.subscribe((txSeq, origin, changes) -> publish(user, names, origin, changes));
      registered.put(token, Boolean.TRUE);
    }
  }

  private void publish(
      Username user,
      Map<OpaqueId, String> names,
      @Nullable Object origin,
      List<MetadataChange> changes) {
    MailboxSession.SessionId session = origin instanceof MailboxSession.SessionId id ? id : SYSTEM;
    Map<OpaqueId, TreeMap<MessageUid, MessageMetaData>> added = new HashMap<>();
    Map<OpaqueId, TreeMap<MessageUid, MessageMetaData>> removed = new HashMap<>();
    Map<OpaqueId, List<UpdatedFlags>> flags = new HashMap<>();
    for (MetadataChange change : changes) {
      switch (change) {
        case MetadataChange.FolderCreated c -> {
          names.put(c.folder().folderId(), c.folder().name());
          dispatch(
              new MailboxEvents.MailboxAdded(
                  session,
                  user,
                  path(user, c.folder().name()),
                  new Ids.FolderId(c.folder().folderId()),
                  Event.EventId.random()),
              c.folder().folderId());
        }
        case MetadataChange.FolderRenamed r -> {
          names.put(r.folderId(), r.newName());
          dispatch(
              new MailboxEvents.MailboxRenamed(
                  session,
                  user,
                  path(user, r.oldName()),
                  new Ids.FolderId(r.folderId()),
                  path(user, r.newName()),
                  Event.EventId.random()),
              r.folderId());
        }
        case MetadataChange.FolderDeleted d -> {
          names.remove(d.folder().folderId());
          dispatch(
              new MailboxEvents.MailboxDeletion(
                  session,
                  user,
                  path(user, d.folder().name()),
                  MailboxACL.OWNER_FULL_ACL,
                  QuotaRoot.quotaRoot("", Optional.empty()),
                  QuotaCountUsage.count(0),
                  QuotaSizeUsage.size(0),
                  new Ids.FolderId(d.folder().folderId()),
                  Event.EventId.random()),
              d.folder().folderId());
        }
        case MetadataChange.MessageAdded a ->
            added
                .computeIfAbsent(a.key().folderId(), k -> new TreeMap<>())
                .put(MessageUid.of(a.key().uid()), metaData(a.key().uid(), a.record()));
        case MetadataChange.MessageRemoved r ->
            removed
                .computeIfAbsent(r.key().folderId(), k -> new TreeMap<>())
                .put(MessageUid.of(r.key().uid()), metaData(r.key().uid(), r.removed()));
        case MetadataChange.FlagsChanged f ->
            flags
                .computeIfAbsent(f.key().folderId(), k -> new java.util.ArrayList<>())
                .add(
                    UpdatedFlags.builder()
                        .uid(MessageUid.of(f.key().uid()))
                        .oldFlags(MessageViews.toJames(f.oldFlags()))
                        .newFlags(MessageViews.toJames(f.newFlags()))
                        .modSeq(ModSeq.of(f.modSeq()))
                        .build());
      }
    }
    added.forEach(
        (folder, uids) ->
            dispatch(
                new MailboxEvents.Added(
                    session,
                    user,
                    path(user, names.getOrDefault(folder, "")),
                    new Ids.FolderId(folder),
                    uids,
                    Event.EventId.random(),
                    origin == null,
                    origin != null,
                    Optional.empty()),
                folder));
    removed.forEach(
        (folder, uids) ->
            dispatch(
                new MailboxEvents.Expunged(
                    session,
                    user,
                    path(user, names.getOrDefault(folder, "")),
                    new Ids.FolderId(folder),
                    uids,
                    Event.EventId.random(),
                    Optional.empty()),
                folder));
    flags.forEach(
        (folder, updates) ->
            dispatch(
                new MailboxEvents.FlagsUpdated(
                    session,
                    user,
                    path(user, names.getOrDefault(folder, "")),
                    new Ids.FolderId(folder),
                    updates,
                    Event.EventId.random()),
                folder));
  }

  private void dispatch(Event event, OpaqueId folder) {
    eventBus
        .dispatch(event, Set.of(new MailboxIdRegistrationKey(new Ids.FolderId(folder))))
        .subscribe();
  }

  private static MessageMetaData metaData(long uid, MessageRecord record) {
    Ids.BlobId messageId = new Ids.BlobId(record.blobId());
    return new MessageMetaData(
        MessageUid.of(uid),
        ModSeq.of(record.modSeq()),
        MessageViews.toJames(record.flags()),
        record.size(),
        new java.util.Date(record.internalDateMillis()),
        Optional.empty(),
        messageId,
        ThreadId.fromBaseMessageId(messageId));
  }

  static MailboxPath path(Username user, String name) {
    return new MailboxPath(MailboxConstants.USER_NAMESPACE, user, name);
  }
}
