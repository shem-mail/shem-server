package org.shem.imap;

import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import org.apache.james.core.Username;
import org.apache.james.mailbox.MailboxManager;
import org.apache.james.mailbox.MailboxSession;
import org.apache.james.mailbox.MessageManager;
import org.apache.james.mailbox.MessageUid;
import org.apache.james.mailbox.SubscriptionManager;
import org.apache.james.mailbox.exception.BadCredentialsException;
import org.apache.james.mailbox.exception.MailboxException;
import org.apache.james.mailbox.exception.MailboxExistsException;
import org.apache.james.mailbox.exception.MailboxNameException;
import org.apache.james.mailbox.exception.MailboxNotFoundException;
import org.apache.james.mailbox.exception.SubscriptionException;
import org.apache.james.mailbox.exception.UnsupportedRightException;
import org.apache.james.mailbox.model.Mailbox;
import org.apache.james.mailbox.model.MailboxACL;
import org.apache.james.mailbox.model.MailboxAnnotation;
import org.apache.james.mailbox.model.MailboxAnnotationKey;
import org.apache.james.mailbox.model.MailboxConstants;
import org.apache.james.mailbox.model.MailboxCounters;
import org.apache.james.mailbox.model.MailboxId;
import org.apache.james.mailbox.model.MailboxMetaData;
import org.apache.james.mailbox.model.MailboxPath;
import org.apache.james.mailbox.model.MessageId;
import org.apache.james.mailbox.model.MessageRange;
import org.apache.james.mailbox.model.MultimailboxesSearchQuery;
import org.apache.james.mailbox.model.ThreadId;
import org.apache.james.mailbox.model.UidValidity;
import org.apache.james.mailbox.model.search.MailboxQuery;
import org.jspecify.annotations.Nullable;
import org.reactivestreams.Publisher;
import org.shem.common.OpaqueId;
import org.shem.mailbox.MailboxLease;
import org.shem.store.SpecialUse;
import org.shem.store.StorageException;
import org.shem.store.metadata.Folder;
import org.shem.store.metadata.MessageKey;
import org.shem.store.metadata.ReadView;
import org.shem.store.metadata.Tx;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * James mailbox manager over Shem leases. Only the authenticated user's private namespace exists;
 * ACLs, annotations, quotas, and multi-mailbox search are not offered (and not advertised).
 * Authentication happens in {@link ShemLoginProcessor}, never through {@link
 * #authenticate(Username, String)}.
 */
final class ShemMailboxManager implements MailboxManager, SubscriptionManager {
  private final EventPublisher events;

  ShemMailboxManager(EventPublisher events) {
    this.events = events;
  }

  EventPublisher events() {
    return events;
  }

  // ---- capabilities ----

  @Override
  public EnumSet<MailboxCapabilities> getSupportedMailboxCapabilities() {
    return EnumSet.of(
        MailboxCapabilities.Move, MailboxCapabilities.Namespace, MailboxCapabilities.UserFlag);
  }

  @Override
  public boolean hasCapability(MailboxCapabilities capability) {
    return getSupportedMailboxCapabilities().contains(capability);
  }

  @Override
  public EnumSet<MessageCapabilities> getSupportedMessageCapabilities() {
    return EnumSet.noneOf(MessageCapabilities.class);
  }

  @Override
  public EnumSet<SearchCapabilities> getSupportedSearchCapabilities() {
    return EnumSet.noneOf(SearchCapabilities.class);
  }

  // ---- sessions ----

  @Override
  public MailboxSession createSystemSession(Username userName) {
    throw new UnsupportedOperationException("Shem has no system sessions with mailbox access");
  }

  @Override
  public AuthorizationStep authenticate(Username givenUserid, String passwd) {
    return refused();
  }

  @Override
  public AuthorizationStep authenticate(Username givenUserid) {
    return refused();
  }

  private static AuthorizationStep refused() {
    return new AuthorizationStep() {
      @Override
      public MailboxSession as(Username other) throws MailboxException {
        throw new BadCredentialsException();
      }

      @Override
      public MailboxSession withoutDelegation() throws MailboxException {
        throw new BadCredentialsException();
      }

      @Override
      public MailboxSession forMatchingUser(java.util.function.Predicate<Username> other)
          throws MailboxException {
        throw new BadCredentialsException();
      }
    };
  }

  @Override
  public void startProcessingRequest(MailboxSession session) {}

  @Override
  public void endProcessingRequest(MailboxSession session) {}

  // ---- folders ----

  @Override
  public MessageManager getMailbox(MailboxPath path, MailboxSession session)
      throws MailboxException {
    MailboxLease lease = Sessions.lease(session);
    String name = name(path, session);
    Folder folder =
        read(lease, view -> view.folderByName(name))
            .orElseThrow(() -> new MailboxNotFoundException(path));
    return new ShemMessageManager(lease, folder, path(session, folder.name()));
  }

  @Override
  public MessageManager getMailbox(MailboxId mailboxId, MailboxSession session)
      throws MailboxException {
    MailboxLease lease = Sessions.lease(session);
    OpaqueId id = Ids.folderOf(mailboxId);
    Folder folder =
        read(lease, view -> view.folder(id))
            .orElseThrow(() -> new MailboxNotFoundException(mailboxId));
    return new ShemMessageManager(lease, folder, path(session, folder.name()));
  }

  @Override
  public Publisher<MessageManager> getMailboxReactive(MailboxId mailboxId, MailboxSession session) {
    return ShemMessageManager.blocking(() -> getMailbox(mailboxId, session));
  }

  @Override
  public Publisher<MessageManager> getMailboxReactive(MailboxPath path, MailboxSession session) {
    return ShemMessageManager.blocking(() -> getMailbox(path, session));
  }

  @Override
  public MessageManager getMailbox(Mailbox mailbox, MailboxSession session)
      throws MailboxException {
    return getMailbox(mailbox.getMailboxId(), session);
  }

  @Override
  public Optional<MailboxId> createMailbox(
      MailboxPath path, CreateOption option, MailboxSession session) throws MailboxException {
    MailboxLease lease = Sessions.lease(session);
    String name = name(path, session);
    if (name.isEmpty()) {
      throw new MailboxNameException("empty mailbox name");
    }
    OpaqueId created =
        write(
            lease,
            session,
            tx -> {
              if (tx.folderByName(name).isPresent()) {
                return null;
              }
              Folder folder = null;
              String[] levels = name.split("\\" + Sessions.DELIMITER, -1);
              StringBuilder current = new StringBuilder();
              for (String level : levels) {
                if (level.isEmpty()) {
                  throw new StorageException(
                      StorageException.Kind.LIMIT_EXCEEDED, "empty hierarchy level");
                }
                if (current.length() > 0) {
                  current.append(Sessions.DELIMITER);
                }
                current.append(level);
                String partial = current.toString();
                Optional<Folder> existing = tx.folderByName(partial);
                folder =
                    existing.isPresent()
                        ? existing.get()
                        : tx.createFolder(partial, SpecialUse.NONE);
                if (option == CreateOption.CREATE_SUBSCRIPTION && existing.isEmpty()) {
                  tx.setSubscribed(partial, true);
                }
              }
              return folder == null ? null : folder.folderId();
            });
    if (created == null) {
      throw new MailboxExistsException(path.getName());
    }
    return Optional.of(new Ids.FolderId(created));
  }

  @Override
  public void deleteMailbox(MailboxPath path, MailboxSession session) throws MailboxException {
    MailboxLease lease = Sessions.lease(session);
    String name = name(path, session);
    if (name.equals(MailboxConstants.INBOX)) {
      throw new MailboxException("INBOX cannot be deleted");
    }
    write(
        lease,
        session,
        tx -> {
          Folder folder =
              tx.folderByName(name)
                  .orElseThrow(
                      () -> new StorageException(StorageException.Kind.NOT_FOUND, "no folder"));
          tx.deleteFolder(folder.folderId());
          return null;
        });
  }

  @Override
  public Mailbox deleteMailbox(MailboxId mailboxId, MailboxSession session)
      throws MailboxException {
    MessageManager manager = getMailbox(mailboxId, session);
    Mailbox entity = manager.getMailboxEntity();
    deleteMailbox(manager.getMailboxPath(), session);
    return entity;
  }

  @Override
  public List<MailboxRenamedResult> renameMailbox(
      MailboxPath from, MailboxPath to, RenameOption option, MailboxSession session)
      throws MailboxException {
    MailboxLease lease = Sessions.lease(session);
    String oldName = name(from, session);
    String newName = name(to, session);
    List<MailboxRenamedResult> results = new ArrayList<>();
    write(
        lease,
        session,
        tx -> {
          if (tx.folderByName(newName).isPresent()) {
            throw new StorageException(StorageException.Kind.CONFLICT, "target exists");
          }
          Folder source =
              tx.folderByName(oldName)
                  .orElseThrow(
                      () -> new StorageException(StorageException.Kind.NOT_FOUND, "no folder"));
          if (oldName.equals(MailboxConstants.INBOX)) {
            // RFC 3501: renaming INBOX moves its messages to the new name and leaves INBOX empty.
            Folder target = tx.createFolder(newName, SpecialUse.NONE);
            for (long uid : tx.uids(source.folderId())) {
              MessageKey key = new MessageKey(source.folderId(), uid);
              tx.copy(key, target.folderId());
              tx.remove(key);
            }
            results.add(new MailboxRenamedResult(new Ids.FolderId(target.folderId()), from, to));
            return null;
          }
          String prefix = oldName + Sessions.DELIMITER;
          for (Folder folder : List.copyOf(tx.folders())) {
            String renamed = null;
            if (folder.name().equals(oldName)) {
              renamed = newName;
            } else if (folder.name().startsWith(prefix)) {
              renamed = newName + folder.name().substring(oldName.length());
            }
            if (renamed != null) {
              tx.renameFolder(folder.folderId(), renamed);
              if (option == RenameOption.RENAME_SUBSCRIPTIONS
                  && tx.subscriptions().contains(folder.name())) {
                tx.setSubscribed(folder.name(), false);
                tx.setSubscribed(renamed, true);
              }
              results.add(
                  new MailboxRenamedResult(
                      new Ids.FolderId(folder.folderId()),
                      path(session, folder.name()),
                      path(session, renamed)));
            }
          }
          return null;
        });
    return results;
  }

  @Override
  public List<MailboxRenamedResult> renameMailbox(
      MailboxId mailboxId, MailboxPath newPath, RenameOption option, MailboxSession session)
      throws MailboxException {
    return renameMailbox(getMailbox(mailboxId, session).getMailboxPath(), newPath, option, session);
  }

  @Override
  public List<MessageRange> copyMessages(
      MessageRange set, MailboxPath from, MailboxPath to, MailboxSession session)
      throws MailboxException {
    return transfer(
        set, getMailbox(from, session).getId(), getMailbox(to, session).getId(), session, false);
  }

  @Override
  public List<MessageRange> copyMessages(
      MessageRange set, MailboxId from, MailboxId to, MailboxSession session)
      throws MailboxException {
    return transfer(set, from, to, session, false);
  }

  @Override
  public List<MessageRange> moveMessages(
      MessageRange set, MailboxPath from, MailboxPath to, MailboxSession session)
      throws MailboxException {
    return transfer(
        set, getMailbox(from, session).getId(), getMailbox(to, session).getId(), session, true);
  }

  @Override
  public List<MessageRange> moveMessages(
      MessageRange set, MailboxId from, MailboxId to, MailboxSession session)
      throws MailboxException {
    return transfer(set, from, to, session, true);
  }

  /** COPY/MOVE in one transaction: new destination UIDs reference the same blobs. */
  private List<MessageRange> transfer(
      MessageRange set, MailboxId from, MailboxId to, MailboxSession session, boolean move)
      throws MailboxException {
    MailboxLease lease = Sessions.lease(session);
    OpaqueId source = Ids.folderOf(from);
    OpaqueId target = Ids.folderOf(to);
    List<MessageUid> created = new ArrayList<>();
    write(
        lease,
        session,
        tx -> {
          if (tx.folder(source).isEmpty() || tx.folder(target).isEmpty()) {
            throw new StorageException(StorageException.Kind.NOT_FOUND, "no folder");
          }
          for (long uid : ShemMessageManager.selected(tx.uids(source), set)) {
            MessageKey key = new MessageKey(source, uid);
            created.add(MessageUid.of(tx.copy(key, target)));
            if (move) {
              tx.remove(key);
            }
          }
          return null;
        });
    return MessageRange.toRanges(created);
  }

  @Override
  public Flux<MailboxMetaData> search(
      MailboxQuery query, MailboxSearchFetchType fetchType, MailboxSession session) {
    return ShemMessageManager.blocking(
            () -> {
              MailboxLease lease = Sessions.lease(session);
              List<MailboxMetaData> result = new ArrayList<>();
              List<Folder> folders = new ArrayList<>(read(lease, ReadView::folders));
              for (Folder folder : folders) {
                MailboxPath path = path(session, folder.name());
                if (!query.isPathMatch(path)) {
                  continue;
                }
                Ids.FolderId id = new Ids.FolderId(folder.folderId());
                Mailbox mailbox = new Mailbox(path, UidValidity.of(folder.uidValidity()), id);
                MailboxCounters counters =
                    fetchType == MailboxSearchFetchType.Counters
                        ? new ShemMessageManager(lease, folder, path).getMailboxCounters(session)
                        : MailboxCounters.empty(id);
                boolean children =
                    folders.stream()
                        .anyMatch(f -> f.name().startsWith(folder.name() + Sessions.DELIMITER));
                result.add(
                    new MailboxMetaData(
                        mailbox,
                        Sessions.DELIMITER,
                        children
                            ? MailboxMetaData.Children.HAS_CHILDREN
                            : MailboxMetaData.Children.HAS_NO_CHILDREN,
                        MailboxMetaData.Selectability.NONE,
                        MailboxACL.OWNER_FULL_ACL,
                        counters));
              }
              return result;
            })
        .flatMapMany(Flux::fromIterable);
  }

  @Override
  public Publisher<MessageId> search(
      MultimailboxesSearchQuery expression, MailboxSession session, long limit) {
    return Flux.error(new org.apache.james.mailbox.exception.UnsupportedSearchException());
  }

  @Override
  public Publisher<MessageId> getThread(ThreadId threadId, MailboxSession session) {
    return Flux.error(new org.apache.james.mailbox.exception.ThreadNotFoundException(threadId));
  }

  @Override
  public Publisher<Boolean> mailboxExists(MailboxPath path, MailboxSession session) {
    return ShemMessageManager.blocking(
        () -> {
          String name = name(path, session);
          return read(Sessions.lease(session), view -> view.folderByName(name).isPresent());
        });
  }

  @Override
  public List<MailboxPath> list(MailboxSession session) throws MailboxException {
    return read(Sessions.lease(session), ReadView::folders).stream()
        .map(f -> path(session, f.name()))
        .toList();
  }

  @Override
  public boolean hasChildren(MailboxPath path, MailboxSession session) throws MailboxException {
    String prefix = name(path, session) + Sessions.DELIMITER;
    return read(Sessions.lease(session), ReadView::folders).stream()
        .anyMatch(f -> f.name().startsWith(prefix));
  }

  @Override
  public Publisher<Boolean> hasChildrenReactive(MailboxPath path, MailboxSession session) {
    return ShemMessageManager.blocking(() -> hasChildren(path, session));
  }

  @Override
  public MessageId.Factory getMessageIdFactory() {
    return Ids.MESSAGE_IDS;
  }

  // ---- subscriptions ----

  @Override
  public void subscribe(MailboxSession session, MailboxPath mailbox) throws SubscriptionException {
    setSubscribed(session, mailbox, true);
  }

  @Override
  public Publisher<Void> subscribeReactive(MailboxPath mailbox, MailboxSession session) {
    return ShemMessageManager.blocking(
            () -> {
              setSubscribed(session, mailbox, true);
              return Boolean.TRUE;
            })
        .then();
  }

  @Override
  public Collection<MailboxPath> subscriptions(MailboxSession session)
      throws SubscriptionException {
    try {
      return read(Sessions.lease(session), ReadView::subscriptions).stream()
          .map(name -> path(session, name))
          .toList();
    } catch (MailboxException e) {
      throw new SubscriptionException(e);
    }
  }

  @Override
  public Publisher<MailboxPath> subscriptionsReactive(MailboxSession session) {
    return ShemMessageManager.blocking(() -> subscriptions(session))
        .flatMapMany(Flux::fromIterable);
  }

  @Override
  public void unsubscribe(MailboxSession session, MailboxPath mailbox)
      throws SubscriptionException {
    setSubscribed(session, mailbox, false);
  }

  @Override
  public Publisher<Void> unsubscribeReactive(MailboxPath mailbox, MailboxSession session) {
    return ShemMessageManager.blocking(
            () -> {
              setSubscribed(session, mailbox, false);
              return Boolean.TRUE;
            })
        .then();
  }

  private void setSubscribed(MailboxSession session, MailboxPath mailbox, boolean subscribed)
      throws SubscriptionException {
    try {
      String name = name(mailbox, session);
      write(
          Sessions.lease(session),
          session,
          tx -> {
            tx.setSubscribed(name, subscribed);
            return null;
          });
    } catch (MailboxException e) {
      throw new SubscriptionException(e);
    }
  }

  // ---- rights: the owner has all rights; nothing else exists ----

  @Override
  public boolean hasRight(MailboxPath path, MailboxACL.Right right, MailboxSession session) {
    return path.belongsTo(session);
  }

  @Override
  public Publisher<Boolean> hasRightReactive(
      MailboxPath path, MailboxACL.Right right, MailboxSession session) {
    return Mono.just(path.belongsTo(session));
  }

  @Override
  public boolean hasRight(Mailbox mailbox, MailboxACL.Right right, MailboxSession session) {
    return mailbox.generateAssociatedPath().belongsTo(session);
  }

  @Override
  public boolean hasRight(MailboxId mailboxId, MailboxACL.Right right, MailboxSession session)
      throws MailboxException {
    getMailbox(mailboxId, session);
    return true;
  }

  @Override
  public List<MailboxACL.Rfc4314Rights> listRights(
      MailboxPath path, MailboxACL.EntryKey identifier, MailboxSession session)
      throws MailboxException {
    throw new UnsupportedRightException();
  }

  @Override
  public List<MailboxACL.Rfc4314Rights> listRights(
      Mailbox mailbox, MailboxACL.EntryKey identifier, MailboxSession session)
      throws MailboxException {
    throw new UnsupportedRightException();
  }

  @Override
  public MailboxACL listRights(MailboxPath path, MailboxSession session) {
    return MailboxACL.OWNER_FULL_ACL;
  }

  @Override
  public Publisher<MailboxACL> listRightsReactive(MailboxPath path, MailboxSession session) {
    return Mono.just(MailboxACL.OWNER_FULL_ACL);
  }

  @Override
  public MailboxACL listRights(MailboxId mailboxId, MailboxSession session) {
    return MailboxACL.OWNER_FULL_ACL;
  }

  @Override
  public Publisher<MailboxACL> listRightsReactive(MailboxId mailboxId, MailboxSession session) {
    return Mono.just(MailboxACL.OWNER_FULL_ACL);
  }

  @Override
  public MailboxACL.Rfc4314Rights myRights(MailboxPath path, MailboxSession session) {
    return path.belongsTo(session) ? MailboxACL.FULL_RIGHTS : MailboxACL.NO_RIGHTS;
  }

  @Override
  public Publisher<MailboxACL.Rfc4314Rights> myRightsReactive(
      MailboxPath path, MailboxSession session) {
    return Mono.just(myRights(path, session));
  }

  @Override
  public Publisher<MailboxACL.Rfc4314Rights> myRights(MailboxId mailboxId, MailboxSession session) {
    return Mono.just(MailboxACL.FULL_RIGHTS);
  }

  @Override
  public MailboxACL.Rfc4314Rights myRights(Mailbox mailbox, MailboxSession session) {
    return myRights(mailbox.generateAssociatedPath(), session);
  }

  @Override
  public void applyRightsCommand(
      MailboxPath path, MailboxACL.ACLCommand command, MailboxSession session)
      throws MailboxException {
    throw new UnsupportedRightException();
  }

  @Override
  public Publisher<Void> applyRightsCommandReactive(
      MailboxPath path, MailboxACL.ACLCommand command, MailboxSession session) {
    return Mono.error(new UnsupportedRightException());
  }

  @Override
  public void applyRightsCommand(
      MailboxId mailboxId, MailboxACL.ACLCommand command, MailboxSession session)
      throws MailboxException {
    throw new UnsupportedRightException();
  }

  @Override
  public void setRights(MailboxPath path, MailboxACL acl, MailboxSession session)
      throws MailboxException {
    throw new UnsupportedRightException();
  }

  @Override
  public void setRights(MailboxId mailboxId, MailboxACL acl, MailboxSession session)
      throws MailboxException {
    throw new UnsupportedRightException();
  }

  // ---- annotations: not supported ----

  @Override
  public List<MailboxAnnotation> getAllAnnotations(MailboxPath path, MailboxSession session) {
    return List.of();
  }

  @Override
  public Publisher<MailboxAnnotation> getAllAnnotationsReactive(
      MailboxPath path, MailboxSession session) {
    return Flux.empty();
  }

  @Override
  public List<MailboxAnnotation> getAnnotationsByKeys(
      MailboxPath path, MailboxSession session, Set<MailboxAnnotationKey> keys) {
    return List.of();
  }

  @Override
  public Publisher<MailboxAnnotation> getAnnotationsByKeysReactive(
      MailboxPath path, MailboxSession session, Set<MailboxAnnotationKey> keys) {
    return Flux.empty();
  }

  @Override
  public List<MailboxAnnotation> getAnnotationsByKeysWithOneDepth(
      MailboxPath path, MailboxSession session, Set<MailboxAnnotationKey> keys) {
    return List.of();
  }

  @Override
  public Publisher<MailboxAnnotation> getAnnotationsByKeysWithOneDepthReactive(
      MailboxPath path, MailboxSession session, Set<MailboxAnnotationKey> keys) {
    return Flux.empty();
  }

  @Override
  public List<MailboxAnnotation> getAnnotationsByKeysWithAllDepth(
      MailboxPath path, MailboxSession session, Set<MailboxAnnotationKey> keys) {
    return List.of();
  }

  @Override
  public Publisher<MailboxAnnotation> getAnnotationsByKeysWithAllDepthReactive(
      MailboxPath path, MailboxSession session, Set<MailboxAnnotationKey> keys) {
    return Flux.empty();
  }

  @Override
  public void updateAnnotations(
      MailboxPath path, MailboxSession session, List<MailboxAnnotation> annotations)
      throws MailboxException {
    throw new MailboxException("annotations are not supported");
  }

  @Override
  public Publisher<Void> updateAnnotationsReactive(
      MailboxPath path, MailboxSession session, List<MailboxAnnotation> annotations) {
    return Mono.error(new MailboxException("annotations are not supported"));
  }

  // ---- helpers ----

  /** Folder name for a path in the session user's namespace; INBOX is case-insensitive. */
  static String name(MailboxPath path, MailboxSession session) throws MailboxException {
    if (!path.belongsTo(session)) {
      throw new MailboxNotFoundException(path);
    }
    path.assertAcceptable(Sessions.DELIMITER);
    String name = path.getName();
    if (name.equalsIgnoreCase(MailboxConstants.INBOX)) {
      return MailboxConstants.INBOX;
    }
    String upper = name.toUpperCase(Locale.ROOT);
    if (upper.startsWith(MailboxConstants.INBOX + Sessions.DELIMITER)) {
      return MailboxConstants.INBOX + name.substring(MailboxConstants.INBOX.length());
    }
    return name;
  }

  static MailboxPath path(MailboxSession session, String name) {
    return new MailboxPath(MailboxConstants.USER_NAMESPACE, session.getUser(), name);
  }

  private static <T extends @Nullable Object> T read(
      MailboxLease lease, org.shem.store.metadata.MetadataStore.ReadBody<T> body)
      throws MailboxException {
    try {
      return lease.read(body);
    } catch (StorageException e) {
      throw ShemMessageManager.storage(e);
    } catch (org.shem.mailbox.RevokedLeaseException e) {
      throw new MailboxException("session no longer authorized", e);
    }
  }

  private static <T extends @Nullable Object> T write(
      MailboxLease lease, MailboxSession session, TxBodyWithStorage<T> body)
      throws MailboxException {
    try {
      return lease.write(session.getSessionId(), body::run);
    } catch (StorageException e) {
      if (e.kind() == StorageException.Kind.CONFLICT) {
        throw new MailboxExistsException("mailbox exists");
      }
      throw ShemMessageManager.storage(e);
    } catch (org.shem.mailbox.RevokedLeaseException e) {
      throw new MailboxException("session no longer authorized", e);
    }
  }

  @FunctionalInterface
  private interface TxBodyWithStorage<T extends @Nullable Object> {
    T run(Tx tx) throws StorageException;
  }
}
