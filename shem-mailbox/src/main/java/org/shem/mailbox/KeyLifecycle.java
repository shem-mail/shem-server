package org.shem.mailbox;

import java.lang.System.Logger.Level;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.shem.common.IdGenerator;
import org.shem.common.ImmutableBytes;
import org.shem.common.OpaqueId;
import org.shem.common.RecordReader;
import org.shem.common.RecordWriter;
import org.shem.crypto.Argon2Parameters;
import org.shem.crypto.Argon2idKdf;
import org.shem.crypto.CryptoException;
import org.shem.crypto.KdfAdmission;
import org.shem.crypto.KeySlot;
import org.shem.crypto.Keyring;
import org.shem.crypto.MailboxPrivateKey;
import org.shem.crypto.MailboxPublicKey;
import org.shem.crypto.MfaFactor;
import org.shem.crypto.Secret;
import org.shem.crypto.SlotDescriptor;
import org.shem.crypto.SlotKind;
import org.shem.crypto.SymmetricKey;
import org.shem.crypto.Totp;
import org.shem.identity.Account;
import org.shem.identity.AccountState;
import org.shem.identity.IdentityException;
import org.shem.identity.IdentityService;
import org.shem.store.StorageException;

/**
 * Self-service key lifecycle: enrollment, password change, app passwords, recovery codes, and key
 * rotation. Every change commits by atomically replacing the sealed keyring; slot files are written
 * before and stale ones removed after, and {@link #resume(MailboxLease)} completes any interrupted
 * step at the next unlock.
 *
 * <p>Limits (see docs/adr/0002): rewrapping does not protect ciphertext or envelopes copied before
 * the change, and removing a slot does not revoke keys already unlocked by an attacker.
 */
public final class KeyLifecycle {
  private static final System.Logger LOG = System.getLogger(KeyLifecycle.class.getName());
  static final String CUTOVER_PROPERTY = "shem.keys.cutover";

  private final IdentityService identity;
  private final MailboxRegistry registry;
  private final KeyFiles keyFiles;
  private final Argon2idKdf kdf;
  private final Argon2Parameters slotParameters;
  private final IdGenerator ids;
  private final SecureRandom random;
  private final Clock clock;
  private final Duration oldKeyRetention;

  public KeyLifecycle(
      IdentityService identity,
      MailboxRegistry registry,
      Argon2idKdf kdf,
      Argon2Parameters slotParameters,
      IdGenerator ids,
      SecureRandom random,
      Clock clock,
      Duration oldKeyRetention) {
    this.identity = identity;
    this.registry = registry;
    this.keyFiles = new KeyFiles(registry.dependencies().paths(), kdf.limits());
    this.kdf = kdf;
    this.slotParameters = slotParameters;
    this.ids = ids;
    this.random = random;
    this.clock = clock;
    this.oldKeyRetention = oldKeyRetention;
  }

  /** Failure of a lifecycle request that the caller can report (HTTP 409/403). */
  public static final class LifecycleException extends Exception {
    private static final long serialVersionUID = 1L;

    public LifecycleException(String message) {
      super(message);
    }
  }

  public List<SlotDescriptor> slots(MailboxLease lease) throws StorageException, CryptoException {
    lease.checkValid();
    return lease.coordinator().withKeys(state -> state.keyring.slots());
  }

  /**
   * Mandatory enrollment: replaces the bootstrap keypair, data root, and master key, creates the
   * user's password slot, deletes the bootstrap slot, and switches routing to the new public key.
   */
  public void enroll(MailboxLease lease, CharSequence newPassword)
      throws LifecycleException,
          StorageException,
          CryptoException,
          IdentityException,
          KdfAdmission.Rejected,
          InterruptedException {
    lease.require(Capability.ENROLL);
    Account account = account(lease);
    if (account.state() != AccountState.PENDING_ENROLLMENT) {
      throw new LifecycleException("account is not awaiting enrollment");
    }
    replaceAllKeys(lease, newPassword);
    resume(lease);
    registry.revokeSlot(lease.mailboxId(), lease.principal().slotId());
  }

  /**
   * User-initiated rotation: like enrollment, for an active account. Other slots (app passwords,
   * recovery codes) wrap the old master key and are removed; the user must recreate them.
   */
  public void rotateKeys(MailboxLease lease, CharSequence password)
      throws LifecycleException,
          StorageException,
          CryptoException,
          IdentityException,
          KdfAdmission.Rejected,
          InterruptedException {
    requireKeyAdmin(lease);
    if (account(lease).state() != AccountState.ACTIVE) {
      throw new LifecycleException("account is not active");
    }
    Set<OpaqueId> removed = replaceAllKeys(lease, password);
    resume(lease);
    for (OpaqueId slotId : removed) {
      // The session that requested the rotation re-proved the password and stays open.
      if (!slotId.equals(lease.principal().slotId())) {
        registry.revokeSlot(lease.mailboxId(), slotId);
      }
    }
  }

  /** Rewraps the master key under a new password; leases from the old password slot end. */
  public void changePassword(MailboxLease lease, CharSequence newPassword)
      throws LifecycleException,
          StorageException,
          CryptoException,
          KdfAdmission.Rejected,
          InterruptedException {
    requireKeyAdmin(lease);
    checkPassword(newPassword);
    List<OpaqueId> replaced =
        replaceSlotsOfKind(lease, SlotKind.PASSWORD, newPassword, "password", KeyFiles.NO_SELECTOR);
    for (OpaqueId old : replaced) {
      if (!old.equals(lease.principal().slotId())) {
        registry.revokeSlot(lease.mailboxId(), old);
      }
    }
    if (lease.principal().slotKind() == SlotKind.RECOVERY) {
      // A recovery code is single-use: consume it and end every other session.
      removeSlot(lease, lease.principal().slotId());
      registry.revokeMailbox(lease.mailboxId());
    }
  }

  /** Creates an app password; the returned secret is shown once and never stored. */
  public Secret createAppPassword(MailboxLease lease, String label)
      throws LifecycleException,
          StorageException,
          CryptoException,
          KdfAdmission.Rejected,
          InterruptedException {
    requireKeyAdmin(lease);
    Set<String> used = new HashSet<>();
    for (KeyFiles.StoredSlot s : keyFiles.slots(lease.mailboxId(), List.of(SlotKind.APP), null)) {
      used.add(s.selector());
    }
    String selector;
    do {
      selector = Credentials.randomGroup(random);
    } while (used.contains(selector));
    Secret password = Credentials.generate(random, selector, 6);
    try {
      addSlot(lease, SlotKind.APP, password, label, selector);
      return password;
    } catch (StorageException | CryptoException | RuntimeException e) {
      password.close();
      throw e;
    }
  }

  /** Generates a new recovery code, replacing any previous one. */
  public Secret createRecoveryCode(MailboxLease lease)
      throws LifecycleException,
          StorageException,
          CryptoException,
          KdfAdmission.Rejected,
          InterruptedException {
    requireKeyAdmin(lease);
    Secret code = Credentials.generate(random, "", 8);
    try (Secret credential = code.copy()) {
      List<OpaqueId> replaced =
          replaceSlotsOfKind(
              lease, SlotKind.RECOVERY, credential, "recovery", KeyFiles.NO_SELECTOR);
      replaced.forEach(old -> registry.revokeSlot(lease.mailboxId(), old));
      return code;
    } catch (StorageException | CryptoException | RuntimeException e) {
      code.close();
      throw e;
    }
  }

  /** Removes a slot and ends its sessions. The last password slot cannot be removed. */
  public void revokeSlot(MailboxLease lease, OpaqueId slotId)
      throws LifecycleException, StorageException, CryptoException {
    requireKeyAdmin(lease);
    removeSlot(lease, slotId);
    registry.revokeSlot(lease.mailboxId(), slotId);
  }

  // ---- resumable steps ----

  /**
   * Completes interrupted lifecycle steps: public-key cutover, metadata re-encryption, retirement
   * of old keys no longer referenced, and removal of slot files the keyring no longer lists.
   */
  public void resume(MailboxLease lease) throws StorageException, CryptoException {
    MailboxCoordinator coordinator = lease.coordinator();
    Set<Integer> pendingVersions = coordinator.keyVersionsOfPendingReceipts();
    boolean[] reencrypted = new boolean[1];
    coordinator.withKeys(
        state -> {
          Keyring keyring = state.keyring;
          OpaqueId mailboxId = lease.mailboxId();
          MailboxPublicKey current = keyring.currentPublicKey();
          Account account =
              identity
                  .account(mailboxId)
                  .orElseThrow(
                      () -> new StorageException(StorageException.Kind.NOT_FOUND, "no account"));
          if (account.publicKey().keyVersion() < current.keyVersion()) {
            try {
              if (account.state() == AccountState.PENDING_ENROLLMENT) {
                identity.completeEnrollment(mailboxId, account.publicKey().keyVersion(), current);
              } else {
                identity.cutoverPublicKey(mailboxId, account.publicKey().keyVersion(), current);
              }
            } catch (IdentityException e) {
              throw new StorageException(
                  StorageException.Kind.UNAVAILABLE, "key cutover failed", e);
            }
            setCutoverTime(coordinator, current.keyVersion());
          }
          if (coordinator.metadata().dataVersion() < keyring.currentDataVersion()) {
            coordinator.reencryptMetadata(state, keyring.currentDataVersion());
            reencrypted[0] = true;
          }
          List<Integer> retireKeys = new ArrayList<>();
          for (int version : keyring.privateKeys().keySet()) {
            if (version != current.keyVersion()
                && !pendingVersions.contains(version)
                && retentionElapsed(coordinator, current.keyVersion())) {
              retireKeys.add(version);
            }
          }
          List<Integer> retireRoots = new ArrayList<>();
          for (int version : keyring.dataVersions()) {
            if (version < coordinator.metadata().dataVersion()) {
              retireRoots.add(version);
            }
          }
          if (!retireKeys.isEmpty() || !retireRoots.isEmpty()) {
            Keyring next = keyring.withRetiredVersions(retireKeys, retireRoots);
            keyFiles.writeKeyring(mailboxId, next.seal(state.masterKey));
            state.keyring = next;
          }
          removeStaleSlotFiles(mailboxId, state.keyring);
          return null;
        });
    if (reencrypted[0]) {
      // Extensions derive their keys from the data root; rebuild them under the new one.
      coordinator.restartExtensions();
    }
  }

  // ---- internals ----

  private Set<OpaqueId> replaceAllKeys(MailboxLease lease, CharSequence password)
      throws LifecycleException,
          StorageException,
          CryptoException,
          KdfAdmission.Rejected,
          InterruptedException {
    checkPassword(password);
    MailboxCoordinator coordinator = lease.coordinator();
    coordinator.importPending(Integer.MAX_VALUE);
    OpaqueId mailboxId = lease.mailboxId();
    OpaqueId slotId = ids.next();
    SymmetricKey newMaster = SymmetricKey.generate(random);
    KeySlot slot;
    try (Secret credential = Secret.utf8(password)) {
      slot =
          KeySlot.create(
              mailboxId,
              slotId,
              SlotKind.PASSWORD,
              credential,
              newMaster,
              slotParameters,
              kdf,
              random);
    } catch (CryptoException | KdfAdmission.Rejected | InterruptedException | RuntimeException e) {
      newMaster.close();
      throw e;
    }
    return coordinator.withKeys(
        state -> {
          Keyring old = state.keyring;
          Set<OpaqueId> removed = new HashSet<>();
          old.slots().forEach(s -> removed.add(s.slotId()));
          int nextKeyVersion =
              old.privateKeys().keySet().stream().mapToInt(Integer::intValue).max().orElse(0) + 1;
          int nextDataVersion =
              old.dataVersions().stream().mapToInt(Integer::intValue).max().orElse(0) + 1;
          Keyring rotated;
          try (Keyring withKeys =
              old.withRotatedKeys(
                  MailboxPrivateKey.generate(nextKeyVersion),
                  SymmetricKey.generate(random),
                  nextDataVersion)) {
            rotated =
                withKeys.withSlots(
                    List.of(
                        new SlotDescriptor(
                            slotId, SlotKind.PASSWORD, "password", clock.instant())));
          }
          try {
            keyFiles.writeSlot(slot, KeyFiles.NO_SELECTOR);
            keyFiles.writeKeyring(mailboxId, rotated.seal(newMaster));
          } catch (StorageException | CryptoException | RuntimeException e) {
            rotated.close();
            newMaster.close();
            throw e;
          }
          state.keyring = rotated;
          state.masterKey = newMaster;
          removeStaleSlotFiles(mailboxId, rotated);
          return removed;
        });
  }

  private List<OpaqueId> replaceSlotsOfKind(
      MailboxLease lease, SlotKind kind, CharSequence credentialText, String label, String selector)
      throws StorageException, CryptoException, KdfAdmission.Rejected, InterruptedException {
    try (Secret credential = Secret.utf8(credentialText)) {
      return replaceSlotsOfKind(lease, kind, credential, label, selector);
    }
  }

  private List<OpaqueId> replaceSlotsOfKind(
      MailboxLease lease, SlotKind kind, Secret credential, String label, String selector)
      throws StorageException, CryptoException, KdfAdmission.Rejected, InterruptedException {
    MailboxCoordinator coordinator = lease.coordinator();
    OpaqueId mailboxId = lease.mailboxId();
    OpaqueId slotId = ids.next();
    KeySlot slot =
        coordinator.withKeys(
            state -> {
              try {
                return KeySlot.create(
                    mailboxId,
                    slotId,
                    kind,
                    credential,
                    state.masterKey,
                    slotParameters,
                    kdf,
                    random);
              } catch (KdfAdmission.Rejected | InterruptedException e) {
                throw new KdfFailure(e);
              }
            });
    return coordinator.withKeys(
        state -> {
          List<OpaqueId> replaced = new ArrayList<>();
          List<SlotDescriptor> next = new ArrayList<>();
          for (SlotDescriptor d : state.keyring.slots()) {
            if (d.kind() == kind) {
              replaced.add(d.slotId());
            } else {
              next.add(d);
            }
          }
          next.add(new SlotDescriptor(slotId, kind, label, clock.instant()));
          Keyring updated = state.keyring.withSlots(next);
          try {
            keyFiles.writeSlot(slot, selector);
            keyFiles.writeKeyring(mailboxId, updated.seal(state.masterKey));
          } catch (StorageException | CryptoException | RuntimeException e) {
            updated.close();
            throw e;
          }
          state.keyring = updated;
          removeStaleSlotFiles(mailboxId, updated);
          return replaced;
        });
  }

  private void addSlot(
      MailboxLease lease, SlotKind kind, Secret credential, String label, String selector)
      throws StorageException, CryptoException, KdfAdmission.Rejected, InterruptedException {
    MailboxCoordinator coordinator = lease.coordinator();
    OpaqueId mailboxId = lease.mailboxId();
    OpaqueId slotId = ids.next();
    SlotDescriptor descriptor;
    try {
      descriptor = new SlotDescriptor(slotId, kind, label, clock.instant());
    } catch (IllegalArgumentException e) {
      throw new StorageException(StorageException.Kind.LIMIT_EXCEEDED, "label too long", e);
    }
    try {
      coordinator.withKeys(
          state -> {
            KeySlot slot;
            try {
              slot =
                  KeySlot.create(
                      mailboxId,
                      slotId,
                      kind,
                      credential,
                      state.masterKey,
                      slotParameters,
                      kdf,
                      random);
            } catch (KdfAdmission.Rejected | InterruptedException e) {
              throw new KdfFailure(e);
            }
            Keyring updated = state.keyring.withSlotAdded(descriptor);
            try {
              keyFiles.writeSlot(slot, selector);
              keyFiles.writeKeyring(mailboxId, updated.seal(state.masterKey));
            } catch (StorageException | CryptoException | RuntimeException e) {
              updated.close();
              throw e;
            }
            state.keyring = updated;
            return null;
          });
    } catch (KdfFailure e) {
      e.rethrow();
    }
  }

  private void removeSlot(MailboxLease lease, OpaqueId slotId)
      throws LifecycleException, StorageException, CryptoException {
    MailboxCoordinator coordinator = lease.coordinator();
    Optional<SlotDescriptor> target = coordinator.withKeys(state -> state.keyring.slot(slotId));
    if (target.isEmpty()) {
      throw new LifecycleException("no such slot");
    }
    long passwords =
        coordinator.withKeys(
            state ->
                state.keyring.slots().stream().filter(s -> s.kind() == SlotKind.PASSWORD).count());
    if (target.get().kind() == SlotKind.PASSWORD && passwords <= 1) {
      throw new LifecycleException("cannot remove the last password");
    }
    coordinator.withKeys(
        state -> {
          Keyring updated = state.keyring.withSlotRemoved(slotId);
          try {
            keyFiles.writeKeyring(lease.mailboxId(), updated.seal(state.masterKey));
          } catch (StorageException | CryptoException | RuntimeException e) {
            updated.close();
            throw e;
          }
          state.keyring = updated;
          removeStaleSlotFiles(lease.mailboxId(), updated);
          return null;
        });
  }

  private void removeStaleSlotFiles(OpaqueId mailboxId, Keyring keyring) throws StorageException {
    for (KeyFiles.StoredSlot stored : keyFiles.allSlots(mailboxId)) {
      if (keyring.slot(stored.slot().slotId()).isEmpty()) {
        keyFiles.deleteSlotFile(stored.file());
      }
    }
  }

  private void setCutoverTime(MailboxCoordinator coordinator, int keyVersion)
      throws StorageException {
    long now = clock.millis();
    coordinator
        .metadata()
        .write(
            tx -> {
              tx.setProperty(
                  CUTOVER_PROPERTY,
                  ImmutableBytes.copyOf(new RecordWriter().u32(keyVersion).i64(now).toByteArray()));
              return null;
            });
  }

  private boolean retentionElapsed(MailboxCoordinator coordinator, int currentVersion)
      throws StorageException {
    Optional<ImmutableBytes> value = coordinator.metadata().read(v -> v.property(CUTOVER_PROPERTY));
    if (value.isEmpty()) {
      return true;
    }
    try {
      RecordReader in = new RecordReader(value.get().toByteArray());
      long version = in.u32();
      long at = in.i64();
      return version != currentVersion || clock.millis() - at >= oldKeyRetention.toMillis();
    } catch (org.shem.common.FormatException e) {
      LOG.log(Level.WARNING, "malformed key cutover marker; retaining old keys");
      return false;
    }
  }

  // ---- second factors (ADR 0014) ----

  /** Non-secret description of a registered second factor. */
  public record FactorInfo(OpaqueId id, MfaFactor.Kind kind, String label, Instant createdAt) {}

  public List<FactorInfo> factors(MailboxLease lease) throws StorageException, CryptoException {
    lease.checkValid();
    return lease
        .coordinator()
        .withKeys(
            state ->
                state.keyring.factors().stream()
                    .map(f -> new FactorInfo(f.id(), f.kind(), f.label(), f.createdAt()))
                    .toList());
  }

  /** Registers a second factor, taking ownership of it. */
  public void addFactor(MailboxLease lease, MfaFactor factor)
      throws LifecycleException, StorageException, CryptoException {
    try {
      requireKeyAdmin(lease);
      lease.checkValid();
    } catch (RuntimeException e) {
      factor.close();
      throw e;
    }
    updateFactors(
        lease,
        current -> {
          List<MfaFactor> next = new ArrayList<>();
          current.forEach(f -> next.add(f.copy()));
          next.add(factor);
          return next;
        });
  }

  /**
   * Removes a factor. The last factor can only be removed from a recovery-code session, which then
   * must register a new one before the account is usable over HTTP again.
   */
  public void removeFactor(MailboxLease lease, OpaqueId factorId)
      throws LifecycleException, StorageException, CryptoException {
    requireKeyAdmin(lease);
    List<FactorInfo> current = factors(lease);
    if (current.stream().noneMatch(f -> f.id().equals(factorId))) {
      throw new LifecycleException("no such factor");
    }
    if (current.size() <= 1 && lease.principal().slotKind() != SlotKind.RECOVERY) {
      throw new LifecycleException("cannot remove the last second factor");
    }
    updateFactors(
        lease,
        list -> {
          List<MfaFactor> next = new ArrayList<>();
          list.stream().filter(f -> !f.id().equals(factorId)).forEach(f -> next.add(f.copy()));
          return next;
        });
  }

  /**
   * Checks a TOTP code against the registered TOTP factors and records the accepted time step, so
   * the same or an earlier code can never be used again.
   */
  public boolean verifyTotp(MailboxLease lease, String code)
      throws StorageException, CryptoException {
    lease.checkValid();
    Instant now = clock.instant();
    return lease
        .coordinator()
        .withKeys(
            state -> {
              for (MfaFactor factor : state.keyring.factors()) {
                if (factor.kind() != MfaFactor.Kind.TOTP) {
                  continue;
                }
                java.util.OptionalLong step =
                    Totp.verify(factor.material(), code, now, factor.counter());
                if (step.isPresent()) {
                  persistCounter(state, lease.mailboxId(), factor.id(), step.getAsLong());
                  return true;
                }
              }
              return false;
            });
  }

  /** Copies of the registered WebAuthn credentials; the caller closes them. */
  public List<MfaFactor> webAuthnCredentials(MailboxLease lease)
      throws StorageException, CryptoException {
    lease.checkValid();
    return lease
        .coordinator()
        .withKeys(
            state ->
                state.keyring.factors().stream()
                    .filter(f -> f.kind() == MfaFactor.Kind.WEBAUTHN)
                    .map(MfaFactor::copy)
                    .toList());
  }

  /**
   * Records a verified WebAuthn assertion's signature counter. A counter that does not increase
   * (other than authenticators that always report zero) indicates a cloned authenticator and is
   * refused.
   */
  public boolean recordWebAuthnUse(MailboxLease lease, OpaqueId factorId, long counter)
      throws StorageException, CryptoException {
    lease.checkValid();
    return lease
        .coordinator()
        .withKeys(
            state -> {
              for (MfaFactor factor : state.keyring.factors()) {
                if (factor.id().equals(factorId) && factor.kind() == MfaFactor.Kind.WEBAUTHN) {
                  if (counter == 0 && factor.counter() == 0) {
                    return true;
                  }
                  if (counter <= factor.counter()) {
                    return false;
                  }
                  persistCounter(state, lease.mailboxId(), factorId, counter);
                  return true;
                }
              }
              return false;
            });
  }

  private void persistCounter(
      MailboxCoordinator.KeyState state, OpaqueId mailboxId, OpaqueId factorId, long counter)
      throws StorageException, CryptoException {
    List<MfaFactor> next = new ArrayList<>();
    for (MfaFactor f : state.keyring.factors()) {
      next.add(f.id().equals(factorId) ? f.withCounter(counter) : f.copy());
    }
    Keyring updated = state.keyring.withFactors(next);
    try {
      keyFiles.writeKeyring(mailboxId, updated.seal(state.masterKey));
    } catch (StorageException | CryptoException | RuntimeException e) {
      updated.close();
      throw e;
    }
    state.keyring = updated;
  }

  private void updateFactors(
      MailboxLease lease, java.util.function.Function<List<MfaFactor>, List<MfaFactor>> change)
      throws StorageException, CryptoException, LifecycleException {
    try {
      lease
          .coordinator()
          .withKeys(
              state -> {
                Keyring updated = state.keyring.withFactors(change.apply(state.keyring.factors()));
                try {
                  keyFiles.writeKeyring(lease.mailboxId(), updated.seal(state.masterKey));
                } catch (StorageException | CryptoException | RuntimeException e) {
                  updated.close();
                  throw e;
                }
                state.keyring = updated;
                return null;
              });
    } catch (IllegalArgumentException e) {
      throw new LifecycleException("too many second factors");
    }
  }

  private Account account(MailboxLease lease) throws StorageException {
    return identity
        .account(lease.mailboxId())
        .orElseThrow(() -> new StorageException(StorageException.Kind.NOT_FOUND, "no account"));
  }

  private static void requireKeyAdmin(MailboxLease lease) {
    lease.require(Capability.KEY_ADMINISTRATION);
  }

  private static void checkPassword(CharSequence password) throws LifecycleException {
    if (!Credentials.isAcceptablePassword(password)) {
      throw new LifecycleException("password does not meet policy");
    }
  }

  /** Carries KDF admission failures out of key actions. */
  private static final class KdfFailure extends RuntimeException {
    private static final long serialVersionUID = 1L;
    private final Exception cause;

    KdfFailure(Exception cause) {
      super(cause);
      this.cause = cause;
    }

    void rethrow() throws KdfAdmission.Rejected, InterruptedException {
      if (cause instanceof KdfAdmission.Rejected r) {
        throw r;
      }
      Thread.currentThread().interrupt();
      throw (InterruptedException) cause;
    }
  }
}
