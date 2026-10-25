package org.shem.mailbox;

import java.net.InetAddress;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import org.jspecify.annotations.Nullable;
import org.shem.common.FormatException;
import org.shem.crypto.Argon2Parameters;
import org.shem.crypto.Argon2idKdf;
import org.shem.crypto.CryptoException;
import org.shem.crypto.KdfAdmission;
import org.shem.crypto.Keyring;
import org.shem.crypto.Secret;
import org.shem.crypto.SlotKind;
import org.shem.crypto.SymmetricKey;
import org.shem.identity.Account;
import org.shem.identity.IdentityService;
import org.shem.store.StorageException;

/**
 * Shared authentication for IMAP, submission, and HTTP. A credential is checked only by unwrapping
 * a key slot; unknown users, missing slots, and wrong credentials all cost one bounded Argon2id run
 * and produce the same {@link AuthenticationException.Reason#INVALID}.
 */
public final class SessionService {
  private final IdentityService identity;
  private final KeyFiles keyFiles;
  private final Argon2idKdf kdf;
  private final Argon2Parameters dummyParameters;
  private final AttemptLimiter limiter;
  private final MailboxRegistry registry;
  private final KeyLifecycle lifecycle;
  private final SecureRandom random;

  public SessionService(
      IdentityService identity,
      Argon2idKdf kdf,
      Argon2Parameters slotParameters,
      AttemptLimiter limiter,
      MailboxRegistry registry,
      KeyLifecycle lifecycle,
      SecureRandom random) {
    this.identity = identity;
    this.keyFiles = new KeyFiles(registry.dependencies().paths(), kdf.limits());
    this.kdf = kdf;
    this.dummyParameters = slotParameters;
    this.limiter = limiter;
    this.registry = registry;
    this.lifecycle = lifecycle;
    this.random = random;
  }

  /**
   * Authenticates with a primary password, bootstrap password, or app password and returns a lease
   * if the resulting principal has {@code required}.
   */
  public MailboxLease authenticate(
      String username, CharSequence credential, InetAddress source, Capability required)
      throws AuthenticationException {
    Optional<String> selector = Credentials.appPasswordSelector(credential);
    List<SlotKind> kinds =
        selector.isPresent()
            ? List.of(SlotKind.APP)
            : List.of(SlotKind.PASSWORD, SlotKind.BOOTSTRAP);
    return unlock(username, credential, source, kinds, selector.orElse(null), required);
  }

  /**
   * Mail client login (IMAP, SMTP submission): system-generated app passwords only (ADR 0015). The
   * primary password, which is protected by a second factor on the HTTP API, never works here;
   * anything that is not an app password gets the same KDF cost, limiter accounting, and generic
   * failure as a wrong one.
   */
  public MailboxLease authenticateMailClient(
      String username, CharSequence credential, InetAddress source, Capability required)
      throws AuthenticationException {
    Optional<String> selector = Credentials.appPasswordSelector(credential);
    // A selector no app password can have: no slot matches, so dummy work runs as for a miss.
    return unlock(
        username, credential, source, List.of(SlotKind.APP), selector.orElse("!"), required);
  }

  /**
   * Web/API login: the primary password or a bootstrap password, never an app password, so a
   * credential handed to a mail client cannot reach account management. The principal's
   * capabilities decide what the session may do.
   */
  public MailboxLease authenticatePrimary(
      String username, CharSequence credential, InetAddress source) throws AuthenticationException {
    return unlock(
        username, credential, source, List.of(SlotKind.PASSWORD, SlotKind.BOOTSTRAP), null, null);
  }

  /** Authenticates with a recovery code; the lease may only replace the password. */
  public MailboxLease authenticateRecovery(String username, CharSequence code, InetAddress source)
      throws AuthenticationException {
    return unlock(
        username, code, source, List.of(SlotKind.RECOVERY), null, Capability.KEY_ADMINISTRATION);
  }

  /** Step-up check: the credential unwraps a primary password slot of the lease's mailbox. */
  public boolean verifyPassword(MailboxLease lease, CharSequence password, InetAddress source)
      throws AuthenticationException {
    lease.checkValid();
    throttle(source);
    try (Secret secret = Secret.utf8(password)) {
      for (KeyFiles.StoredSlot stored :
          keyFiles.slots(lease.mailboxId(), List.of(SlotKind.PASSWORD), null)) {
        try {
          stored.slot().unwrap(secret, kdf).close();
          return true;
        } catch (CryptoException e) {
          // try the next slot
        }
      }
      limiter.recordFailure(source);
      return false;
    } catch (StorageException e) {
      throw new AuthenticationException(AuthenticationException.Reason.UNAVAILABLE, null);
    } catch (KdfAdmission.Rejected e) {
      throw new AuthenticationException(
          AuthenticationException.Reason.THROTTLED, Duration.ofSeconds(5));
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new AuthenticationException(AuthenticationException.Reason.UNAVAILABLE, null);
    }
  }

  private MailboxLease unlock(
      String username,
      CharSequence credential,
      InetAddress source,
      List<SlotKind> kinds,
      @Nullable String selector,
      @Nullable Capability required)
      throws AuthenticationException {
    throttle(source);
    Optional<Account> account = identity.loginAccount(username);
    try (Secret secret = Secret.utf8(credential)) {
      List<KeyFiles.StoredSlot> candidates =
          account.isPresent()
              ? keyFiles.slots(account.get().mailboxId(), kinds, selector)
              : List.of();
      if (candidates.isEmpty()) {
        dummyDerivation(secret);
        limiter.recordFailure(source);
        throw new AuthenticationException(AuthenticationException.Reason.INVALID, null);
      }
      Account acct = account.get();
      byte[] sealedKeyring = keyFiles.readKeyring(acct.mailboxId());
      for (KeyFiles.StoredSlot stored : candidates) {
        SymmetricKey master;
        try {
          master = stored.slot().unwrap(secret, kdf);
        } catch (CryptoException e) {
          continue;
        }
        Keyring keyring;
        try {
          keyring = Keyring.open(sealedKeyring, acct.mailboxId(), master);
        } catch (CryptoException e) {
          // Credential was right but the slot belongs to a superseded master key (interrupted
          // change).
          master.close();
          continue;
        }
        if (keyring.slot(stored.slot().slotId()).isEmpty()) {
          keyring.close();
          master.close();
          continue;
        }
        Principal principal =
            new Principal(
                acct.mailboxId(),
                acct.address(),
                stored.slot().slotId(),
                stored.slot().kind(),
                Capability.forSlot(stored.slot().kind()));
        if (required != null && !principal.can(required)) {
          keyring.close();
          master.close();
          throw new AuthenticationException(AuthenticationException.Reason.NOT_PERMITTED, null);
        }
        MailboxLease lease = registry.attach(principal, keyring, master);
        try {
          lifecycle.resume(lease);
        } catch (StorageException | CryptoException e) {
          lease.close();
          throw new AuthenticationException(AuthenticationException.Reason.UNAVAILABLE, null);
        }
        return lease;
      }
      limiter.recordFailure(source);
      throw new AuthenticationException(AuthenticationException.Reason.INVALID, null);
    } catch (StorageException | FormatException e) {
      throw new AuthenticationException(AuthenticationException.Reason.UNAVAILABLE, null);
    } catch (KdfAdmission.Rejected e) {
      throw new AuthenticationException(
          AuthenticationException.Reason.THROTTLED, Duration.ofSeconds(5));
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new AuthenticationException(AuthenticationException.Reason.UNAVAILABLE, null);
    }
  }

  private void throttle(InetAddress source) throws AuthenticationException {
    Optional<Duration> blocked = limiter.blockedFor(source);
    if (blocked.isPresent()) {
      throw new AuthenticationException(AuthenticationException.Reason.THROTTLED, blocked.get());
    }
  }

  /** Comparable work for unknown users and missing slots. */
  private void dummyDerivation(Secret secret) throws KdfAdmission.Rejected, InterruptedException {
    byte[] salt = new byte[16];
    random.nextBytes(salt);
    try {
      kdf.derive(secret, salt, dummyParameters).close();
    } catch (CryptoException e) {
      // Parameters come from configuration; a failure here is not attributable to the user.
    }
  }
}
