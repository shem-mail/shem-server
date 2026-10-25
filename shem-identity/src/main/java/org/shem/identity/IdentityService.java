package org.shem.identity;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;
import org.shem.common.DurableFiles;
import org.shem.common.FormatException;
import org.shem.common.IdGenerator;
import org.shem.common.OpaqueId;
import org.shem.crypto.MailboxPublicKey;

/**
 * Owns the routing directory. Reads use an immutable snapshot; writes are serialized, validated,
 * durably persisted, and only then published. Holds no decryption capability.
 */
public final class IdentityService {
  /** Notified after a committed change, for example to revoke sessions of a blocked account. */
  @FunctionalInterface
  public interface Listener {
    void accountChanged(Account before, Account after);
  }

  private static final int MAX_ALIAS_DEPTH = 8;
  private final Path file;
  private final Clock clock;
  private final IdGenerator ids;
  private final DeliveryPolicy deliveryPolicy;
  private final Duration recreationWaitingPeriod;
  private final AtomicReference<Directory> current;
  private final Object writeLock = new Object();
  private final List<Listener> listeners = new CopyOnWriteArrayList<>();

  private IdentityService(
      Path file,
      Clock clock,
      IdGenerator ids,
      DeliveryPolicy deliveryPolicy,
      Duration recreationWaitingPeriod,
      Directory initial) {
    this.file = file;
    this.clock = clock;
    this.ids = ids;
    this.deliveryPolicy = deliveryPolicy;
    this.recreationWaitingPeriod = recreationWaitingPeriod;
    this.current = new AtomicReference<>(initial);
  }

  /** Opens or initializes the directory file; corruption fails startup rather than resetting. */
  public static IdentityService open(
      Path file,
      Clock clock,
      IdGenerator ids,
      DeliveryPolicy deliveryPolicy,
      Duration recreationWaitingPeriod)
      throws IOException, FormatException {
    Path parent = file.toAbsolutePath().getParent();
    if (parent != null) {
      DurableFiles.createPrivateDirectories(parent);
    }
    Directory initial;
    try {
      initial = DirectoryCodec.decode(Files.readAllBytes(file));
    } catch (NoSuchFileException e) {
      initial = Directory.empty();
    }
    return new IdentityService(file, clock, ids, deliveryPolicy, recreationWaitingPeriod, initial);
  }

  public void subscribe(Listener listener) {
    listeners.add(listener);
  }

  public Directory directory() {
    return current.get();
  }

  // ---- Delivery and authentication lookups (work while mailboxes are locked) ----

  /**
   * Resolves a recipient to the accounts it delivers to. Returns an empty list for unknown or
   * non-accepting recipients; callers apply their anti-enumeration policy.
   */
  public List<RecipientRoute> resolveRecipient(EmailAddress address) throws IdentityException {
    Directory directory = current.get();
    return directory.expand(address, MAX_ALIAS_DEPTH).stream()
        .filter(a -> deliveryPolicy.accepts(a.state()))
        .map(a -> new RecipientRoute(a.mailboxId(), a.publicKey(), a.quotaBytes()))
        .toList();
  }

  public boolean isLocalDomain(String domain) {
    return current.get().isLocalDomain(domain);
  }

  /** The account a login name refers to, if it may authenticate. */
  public Optional<Account> loginAccount(String username) {
    EmailAddress address;
    try {
      address = EmailAddress.parse(username);
    } catch (IllegalArgumentException e) {
      return Optional.empty();
    }
    return current
        .get()
        .accountByAddress(address)
        .filter(a -> a.state().allowsAuthentication())
        .filter(
            a ->
                a.bootstrapExpiresAt() == null || clock.instant().isBefore(a.bootstrapExpiresAt()));
  }

  public Optional<Account> account(OpaqueId mailboxId) {
    return current.get().account(mailboxId);
  }

  /** Whether {@code mailboxId} may use {@code identity} as envelope or header sender. */
  public boolean mayUseSenderIdentity(OpaqueId mailboxId, EmailAddress identity) {
    Directory directory = current.get();
    Optional<Account> own = directory.accountByAddress(identity);
    if (own.isPresent()) {
      return own.get().mailboxId().equals(mailboxId);
    }
    return directory
        .aliasByAddress(identity)
        .map(alias -> alias.senders().contains(mailboxId))
        .orElse(false);
  }

  // ---- Administration ----

  public Domain createDomain(String name) throws IdentityException {
    String canonical = canonicalDomain(name);
    return mutate(
        d -> {
          if (d.domainByName(canonical).isPresent()) {
            throw new IdentityException(IdentityException.Reason.CONFLICT, "domain exists");
          }
          Domain domain = new Domain(ids.next(), canonical, clock.instant(), null, 1);
          Map<OpaqueId, Domain> domains = new HashMap<>(d.domainMap());
          domains.put(domain.domainId(), domain);
          return new Change<>(
              new Directory(d.generation() + 1, domains, d.accountMap(), d.aliasMap()), domain);
        });
  }

  public void deleteDomain(OpaqueId domainId, long expectedVersion) throws IdentityException {
    mutate(
        d -> {
          Domain domain = requireDomain(d, domainId);
          checkVersion(domain.version(), expectedVersion);
          boolean inUse =
              d.accountMap().values().stream()
                      .anyMatch(
                          a -> a.domainId().equals(domainId) && a.state() != AccountState.DELETED)
                  || d.aliasMap().values().stream()
                      .anyMatch(a -> a.address().domain().equals(domain.name()));
          if (inUse) {
            throw new IdentityException(IdentityException.Reason.CONFLICT, "domain in use");
          }
          Map<OpaqueId, Domain> domains = new HashMap<>(d.domainMap());
          domains.remove(domainId);
          return new Change<>(
              new Directory(d.generation() + 1, domains, d.accountMap(), d.aliasMap()), domain);
        });
  }

  public Domain setDkimSelector(OpaqueId domainId, String selector) throws IdentityException {
    if (!selector.matches("[a-z0-9][a-z0-9-]{0,62}")) {
      throw new IdentityException(IdentityException.Reason.INVALID, "invalid selector");
    }
    return mutate(
        d -> {
          Domain updated = requireDomain(d, domainId).withDkimSelector(selector);
          Map<OpaqueId, Domain> domains = new HashMap<>(d.domainMap());
          domains.put(domainId, updated);
          return new Change<>(
              new Directory(d.generation() + 1, domains, d.accountMap(), d.aliasMap()), updated);
        });
  }

  /**
   * Registers a new account with its bootstrap public key. The mailbox id is supplied by the
   * provisioning service, which has already created the mailbox's key files. A deleted address can
   * be recreated only after the waiting period, and always gets a new mailbox id.
   */
  public Account createAccount(
      OpaqueId mailboxId,
      EmailAddress address,
      MailboxPublicKey bootstrapKey,
      long quotaBytes,
      Duration bootstrapValidity)
      throws IdentityException {
    Instant now = clock.instant();
    return mutate(
        d -> {
          Domain domain =
              d.domainByName(address.domain())
                  .orElseThrow(
                      () ->
                          new IdentityException(
                              IdentityException.Reason.NOT_FOUND, "domain not hosted"));
          if (d.accountByAddress(address).isPresent() || d.aliasByAddress(address).isPresent()) {
            throw new IdentityException(IdentityException.Reason.CONFLICT, "address in use");
          }
          if (d.account(mailboxId).isPresent()) {
            throw new IdentityException(IdentityException.Reason.CONFLICT, "mailbox id reused");
          }
          for (Account old : d.accountMap().values()) {
            if (old.address().equals(address)
                && old.deletionRequestedAt() != null
                && now.isBefore(old.deletionRequestedAt().plus(recreationWaitingPeriod))) {
              throw new IdentityException(
                  IdentityException.Reason.CONFLICT, "address in recreation waiting period");
            }
          }
          Account account =
              new Account(
                  mailboxId,
                  address,
                  domain.domainId(),
                  AccountState.PENDING_ENROLLMENT,
                  bootstrapKey,
                  quotaBytes,
                  now,
                  now.plus(bootstrapValidity),
                  null,
                  1);
          Map<OpaqueId, Account> accounts = new HashMap<>(d.accountMap());
          accounts.put(mailboxId, account);
          return new Change<>(
              new Directory(d.generation() + 1, d.domainMap(), accounts, d.aliasMap()), account);
        });
  }

  public Account changeState(OpaqueId mailboxId, long expectedVersion, AccountState next)
      throws IdentityException {
    return updateAccount(
        mailboxId,
        expectedVersion,
        a -> {
          if (!a.state().canTransitionTo(next)) {
            throw new IdentityException(IdentityException.Reason.CONFLICT, "invalid transition");
          }
          return a.withState(next, clock.instant());
        });
  }

  public Account changeQuota(OpaqueId mailboxId, long expectedVersion, long quotaBytes)
      throws IdentityException {
    if (quotaBytes < 0) {
      throw new IdentityException(IdentityException.Reason.INVALID, "negative quota");
    }
    return updateAccount(mailboxId, expectedVersion, a -> a.withQuota(quotaBytes));
  }

  /**
   * Atomically switches future deliveries to a new public key. Called by the key service only after
   * the new keyring (retaining the old private key) is durable.
   */
  public Account cutoverPublicKey(
      OpaqueId mailboxId, int expectedCurrentKeyVersion, MailboxPublicKey next)
      throws IdentityException {
    return updateAccount(
        mailboxId,
        -1,
        a -> {
          if (a.publicKey().keyVersion() != expectedCurrentKeyVersion) {
            throw new IdentityException(
                IdentityException.Reason.VERSION_MISMATCH, "public key changed concurrently");
          }
          return a.withPublicKey(next);
        });
  }

  /** Completes enrollment: activates the account with its new user-owned key. */
  public Account completeEnrollment(
      OpaqueId mailboxId, int bootstrapKeyVersion, MailboxPublicKey next) throws IdentityException {
    return updateAccount(
        mailboxId,
        -1,
        a -> {
          if (a.state() != AccountState.PENDING_ENROLLMENT) {
            throw new IdentityException(
                IdentityException.Reason.CONFLICT, "not pending enrollment");
          }
          if (a.publicKey().keyVersion() != bootstrapKeyVersion) {
            throw new IdentityException(
                IdentityException.Reason.VERSION_MISMATCH, "public key changed concurrently");
          }
          return a.withPublicKey(next).withState(AccountState.ACTIVE, clock.instant());
        });
  }

  public Alias createAlias(EmailAddress address, List<EmailAddress> targets, List<OpaqueId> senders)
      throws IdentityException {
    return mutate(
        d -> {
          if (!d.isLocalDomain(address.domain())) {
            throw new IdentityException(IdentityException.Reason.NOT_FOUND, "domain not hosted");
          }
          if (d.accountByAddress(address).isPresent() || d.aliasByAddress(address).isPresent()) {
            throw new IdentityException(IdentityException.Reason.CONFLICT, "address in use");
          }
          Alias alias;
          try {
            alias = new Alias(ids.next(), address, targets, senders, 1);
          } catch (IllegalArgumentException e) {
            throw new IdentityException(IdentityException.Reason.INVALID, "invalid alias", e);
          }
          return new Change<>(withAlias(d, alias), alias);
        });
  }

  public Alias updateAlias(
      OpaqueId aliasId, long expectedVersion, List<EmailAddress> targets, List<OpaqueId> senders)
      throws IdentityException {
    return mutate(
        d -> {
          Alias existing =
              d.alias(aliasId)
                  .orElseThrow(
                      () -> new IdentityException(IdentityException.Reason.NOT_FOUND, "no alias"));
          checkVersion(existing.version(), expectedVersion);
          Alias alias;
          try {
            alias =
                new Alias(aliasId, existing.address(), targets, senders, existing.version() + 1);
          } catch (IllegalArgumentException e) {
            throw new IdentityException(IdentityException.Reason.INVALID, "invalid alias", e);
          }
          return new Change<>(withAlias(d, alias), alias);
        });
  }

  public void deleteAlias(OpaqueId aliasId, long expectedVersion) throws IdentityException {
    mutate(
        d -> {
          Alias existing =
              d.alias(aliasId)
                  .orElseThrow(
                      () -> new IdentityException(IdentityException.Reason.NOT_FOUND, "no alias"));
          checkVersion(existing.version(), expectedVersion);
          Map<OpaqueId, Alias> aliases = new HashMap<>(d.aliasMap());
          aliases.remove(aliasId);
          return new Change<>(
              new Directory(d.generation() + 1, d.domainMap(), d.accountMap(), aliases), existing);
        });
  }

  // ---- Internals ----

  private Directory withAlias(Directory d, Alias alias) throws IdentityException {
    for (EmailAddress target : alias.targets()) {
      if (!d.isLocalDomain(target.domain())) {
        throw new IdentityException(IdentityException.Reason.INVALID, "alias target not local");
      }
    }
    for (OpaqueId sender : alias.senders()) {
      if (d.account(sender).isEmpty()) {
        throw new IdentityException(IdentityException.Reason.INVALID, "unknown sender mailbox");
      }
    }
    Map<OpaqueId, Alias> aliases = new HashMap<>(d.aliasMap());
    aliases.put(alias.aliasId(), alias);
    Directory next = new Directory(d.generation() + 1, d.domainMap(), d.accountMap(), aliases);
    next.expand(alias.address(), MAX_ALIAS_DEPTH); // rejects cycles and excessive depth
    return next;
  }

  private Account updateAccount(OpaqueId mailboxId, long expectedVersion, AccountUpdate update)
      throws IdentityException {
    Account[] before = new Account[1];
    Account after =
        mutate(
            d -> {
              Account account =
                  d.account(mailboxId)
                      .orElseThrow(
                          () ->
                              new IdentityException(
                                  IdentityException.Reason.NOT_FOUND, "no account"));
              if (expectedVersion >= 0) {
                checkVersion(account.version(), expectedVersion);
              }
              Account updated = update.apply(account);
              before[0] = account;
              Map<OpaqueId, Account> accounts = new HashMap<>(d.accountMap());
              accounts.put(mailboxId, updated);
              return new Change<>(
                  new Directory(d.generation() + 1, d.domainMap(), accounts, d.aliasMap()),
                  updated);
            });
    for (Listener listener : listeners) {
      listener.accountChanged(before[0], after);
    }
    return after;
  }

  private static void checkVersion(long actual, long expected) throws IdentityException {
    if (actual != expected) {
      throw new IdentityException(IdentityException.Reason.VERSION_MISMATCH, "stale version");
    }
  }

  private static Domain requireDomain(Directory d, OpaqueId domainId) throws IdentityException {
    return d.domain(domainId)
        .orElseThrow(() -> new IdentityException(IdentityException.Reason.NOT_FOUND, "no domain"));
  }

  private static String canonicalDomain(String name) throws IdentityException {
    try {
      return EmailAddress.canonicalDomain(name);
    } catch (IllegalArgumentException e) {
      throw new IdentityException(IdentityException.Reason.INVALID, "invalid domain", e);
    }
  }

  private <T> T mutate(Mutation<T> mutation) throws IdentityException {
    synchronized (writeLock) {
      Change<T> change = mutation.apply(current.get());
      try {
        DurableFiles.writeAtomically(file, DirectoryCodec.encode(change.directory()));
      } catch (IOException e) {
        throw new IdentityException(IdentityException.Reason.STORAGE, "directory write failed", e);
      }
      current.set(change.directory());
      return change.result();
    }
  }

  private record Change<T>(Directory directory, T result) {}

  @FunctionalInterface
  private interface Mutation<T> {
    Change<T> apply(Directory directory) throws IdentityException;
  }

  @FunctionalInterface
  private interface AccountUpdate {
    Account apply(Account account) throws IdentityException;
  }
}
