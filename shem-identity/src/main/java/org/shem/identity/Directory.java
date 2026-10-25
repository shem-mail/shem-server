package org.shem.identity;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.shem.common.OpaqueId;

/** Immutable snapshot of the routing directory; readers never block writers. */
public final class Directory {
  private final long generation;
  private final Map<OpaqueId, Domain> domains;
  private final Map<OpaqueId, Account> accounts;
  private final Map<OpaqueId, Alias> aliases;
  private final Map<String, OpaqueId> domainsByName = new HashMap<>();
  private final Map<EmailAddress, OpaqueId> liveAccountsByAddress = new HashMap<>();
  private final Map<EmailAddress, OpaqueId> aliasesByAddress = new HashMap<>();

  Directory(
      long generation,
      Map<OpaqueId, Domain> domains,
      Map<OpaqueId, Account> accounts,
      Map<OpaqueId, Alias> aliases) {
    this.generation = generation;
    this.domains = Map.copyOf(domains);
    this.accounts = Map.copyOf(accounts);
    this.aliases = Map.copyOf(aliases);
    this.domains.values().forEach(d -> domainsByName.put(d.name(), d.domainId()));
    for (Account account : this.accounts.values()) {
      if (account.state() != AccountState.DELETED) {
        liveAccountsByAddress.put(account.address(), account.mailboxId());
      }
    }
    this.aliases.values().forEach(a -> aliasesByAddress.put(a.address(), a.aliasId()));
  }

  static Directory empty() {
    return new Directory(0, Map.of(), Map.of(), Map.of());
  }

  public long generation() {
    return generation;
  }

  public List<Domain> domains() {
    return List.copyOf(domains.values());
  }

  public Optional<Domain> domain(OpaqueId domainId) {
    return Optional.ofNullable(domains.get(domainId));
  }

  public Optional<Domain> domainByName(String name) {
    OpaqueId id = domainsByName.get(name);
    return id == null ? Optional.empty() : Optional.ofNullable(domains.get(id));
  }

  public boolean isLocalDomain(String domain) {
    return domainsByName.containsKey(domain);
  }

  public List<Account> accounts() {
    return List.copyOf(accounts.values());
  }

  public Optional<Account> account(OpaqueId mailboxId) {
    return Optional.ofNullable(accounts.get(mailboxId));
  }

  /** The non-deleted account owning {@code address}, if any. */
  public Optional<Account> accountByAddress(EmailAddress address) {
    OpaqueId id = liveAccountsByAddress.get(address);
    return id == null ? Optional.empty() : Optional.ofNullable(accounts.get(id));
  }

  public List<Alias> aliases() {
    return List.copyOf(aliases.values());
  }

  public Optional<Alias> alias(OpaqueId aliasId) {
    return Optional.ofNullable(aliases.get(aliasId));
  }

  public Optional<Alias> aliasByAddress(EmailAddress address) {
    OpaqueId id = aliasesByAddress.get(address);
    return id == null ? Optional.empty() : Optional.ofNullable(aliases.get(id));
  }

  /**
   * Expands an address to the set of accounts it reaches. Throws if an alias chain cycles or is
   * deeper than {@code maxDepth}.
   */
  public List<Account> expand(EmailAddress address, int maxDepth) throws IdentityException {
    List<Account> result = new ArrayList<>();
    expand(address, maxDepth, new ArrayList<>(), result);
    return result;
  }

  private void expand(
      EmailAddress address, int depthLeft, List<EmailAddress> path, List<Account> result)
      throws IdentityException {
    if (path.contains(address)) {
      throw new IdentityException(IdentityException.Reason.ALIAS_CYCLE, "alias cycle");
    }
    if (depthLeft < 0) {
      throw new IdentityException(IdentityException.Reason.ALIAS_CYCLE, "alias chain too deep");
    }
    Optional<Account> account = accountByAddress(address);
    if (account.isPresent()) {
      if (!result.contains(account.get())) {
        result.add(account.get());
      }
      return;
    }
    Optional<Alias> alias = aliasByAddress(address);
    if (alias.isEmpty()) {
      return;
    }
    path.add(address);
    for (EmailAddress target : alias.get().targets()) {
      expand(target, depthLeft - 1, path, result);
    }
    path.remove(path.size() - 1);
  }

  Map<OpaqueId, Domain> domainMap() {
    return domains;
  }

  Map<OpaqueId, Account> accountMap() {
    return accounts;
  }

  Map<OpaqueId, Alias> aliasMap() {
    return aliases;
  }
}
