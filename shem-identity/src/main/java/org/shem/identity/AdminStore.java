package org.shem.identity;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.regex.Pattern;
import org.jspecify.annotations.Nullable;
import org.shem.common.DurableFiles;
import org.shem.common.FormatException;
import org.shem.common.IdGenerator;
import org.shem.common.ImmutableBytes;
import org.shem.common.OpaqueId;
import org.shem.common.RecordReader;
import org.shem.common.RecordWriter;
import org.shem.crypto.Argon2Parameters;
import org.shem.crypto.Argon2idKdf;
import org.shem.crypto.AssociatedData;
import org.shem.crypto.CryptoException;
import org.shem.crypto.KdfAdmission;
import org.shem.crypto.KeySlot;
import org.shem.crypto.Purpose;
import org.shem.crypto.Secret;
import org.shem.crypto.SlotKind;
import org.shem.crypto.SymmetricKey;
import org.shem.crypto.Totp;

/**
 * Server administrators (ADR 0016). Administrators are not mailboxes and can never unlock one. Each
 * has a random admin key protected by an Argon2id key slot under the admin password (so a correct
 * password is proven by unwrapping, with no separate verification hash), and that key seals the
 * admin's mandatory TOTP secret. A copied {@code admins.bin} therefore yields neither the password
 * nor the second factor without breaking Argon2id. Only the TOTP replay step is stored in clear.
 *
 * <p>An administrator created by the first-run bootstrap (ADR 0021) starts in <em>setup</em> state:
 * its slot is a {@link SlotKind#BOOTSTRAP} slot under an initial password, it has no TOTP secret
 * yet, and the initial password expires. The only thing it can do is {@link #completeSetup}, which
 * replaces the password, enrolls TOTP, and re-keys the administrator.
 *
 * <p>File format {@code SHAD}: version 1 holds only active administrators; version 2 adds a state
 * byte and a setup expiry per administrator. Version 1 is written while no administrator is in
 * setup state, so existing deployments keep a file older releases can read.
 */
public final class AdminStore {
  private static final byte[] MAGIC = {'S', 'H', 'A', 'D'};
  private static final int VERSION_1 = 1;
  private static final int VERSION_2 = 2;

  /** Version of the TOTP seal's authenticated context; independent of the file version. */
  private static final int FACTOR_CONTEXT_VERSION = 1;

  private static final int STATE_ACTIVE = 0;
  private static final int STATE_SETUP = 1;

  /** Name of the generated initial-password file, next to {@code admins.bin}. */
  public static final String INITIAL_PASSWORD_FILE = "initial-password";

  private static final int MAX_ADMINS = 32;
  private static final Pattern NAME = Pattern.compile("[a-z0-9][a-z0-9._-]{0,31}");

  /** A failed administration change; messages are safe to show. */
  public static final class AdminException extends Exception {
    private static final long serialVersionUID = 1L;

    public AdminException(String message) {
      super(message);
    }
  }

  /**
   * One administrator. In setup state {@code sealedTotp} is empty and {@code setupExpires} is set;
   * when active, {@code setupExpires} is null.
   */
  private record Admin(
      OpaqueId id,
      String name,
      ImmutableBytes slot,
      ImmutableBytes sealedTotp,
      long totpStep,
      Instant created,
      @Nullable Instant setupExpires) {
    boolean inSetup() {
      return setupExpires != null;
    }
  }

  /** A password-verified administrator; holds the admin key until closed. */
  public static final class Verified implements AutoCloseable {
    private final OpaqueId id;
    private final String name;
    private final SymmetricKey key;
    private final boolean setupRequired;

    private Verified(OpaqueId id, String name, SymmetricKey key, boolean setupRequired) {
      this.id = id;
      this.name = name;
      this.key = key;
      this.setupRequired = setupRequired;
    }

    /**
     * True when this administrator signed in with its initial password and must {@link
     * #completeSetup complete setup} before anything else.
     */
    public boolean setupRequired() {
      return setupRequired;
    }

    public OpaqueId id() {
      return id;
    }

    public String name() {
      return name;
    }

    @Override
    public void close() {
      key.close();
    }
  }

  private final Path file;
  private final Argon2idKdf kdf;
  private final Argon2Parameters parameters;
  private final IdGenerator ids;
  private final SecureRandom random;
  private final Clock clock;
  private final List<Admin> admins = new ArrayList<>();

  private AdminStore(
      Path file,
      Argon2idKdf kdf,
      Argon2Parameters parameters,
      IdGenerator ids,
      SecureRandom random,
      Clock clock) {
    this.file = file;
    this.kdf = kdf;
    this.parameters = parameters;
    this.ids = ids;
    this.random = random;
    this.clock = clock;
  }

  public static AdminStore open(
      Path file,
      Argon2idKdf kdf,
      Argon2Parameters parameters,
      IdGenerator ids,
      SecureRandom random,
      Clock clock)
      throws IOException, FormatException {
    AdminStore store = new AdminStore(file, kdf, parameters, ids, random, clock);
    if (Files.exists(file)) {
      store.admins.addAll(decode(Files.readAllBytes(file)));
    }
    return store;
  }

  public synchronized List<String> names() {
    return admins.stream().map(Admin::name).toList();
  }

  public synchronized boolean isEmpty() {
    return admins.isEmpty();
  }

  /** Names of administrators that have not completed first-login setup. */
  public synchronized List<String> namesPendingSetup() {
    return admins.stream().filter(Admin::inSetup).map(Admin::name).toList();
  }

  /** The generated initial-password file, present only until setup completes. */
  public Path initialPasswordFile() {
    return file.resolveSibling(INITIAL_PASSWORD_FILE);
  }

  /**
   * Creates an administrator that must complete setup (ADR 0021): {@code password} opens a
   * bootstrap slot until {@code expires}, after which it is refused.
   */
  public synchronized void createForSetup(String name, CharSequence password, Instant expires)
      throws AdminException,
          IOException,
          CryptoException,
          KdfAdmission.Rejected,
          InterruptedException {
    validateNew(name, password);
    if (!expires.isAfter(clock.instant())) {
      throw new AdminException("setup expiry must be in the future");
    }
    OpaqueId id = ids.next();
    try (SymmetricKey key = SymmetricKey.generate(random);
        Secret credential = Secret.utf8(password)) {
      KeySlot slot =
          KeySlot.create(
              id, ids.next(), SlotKind.BOOTSTRAP, credential, key, parameters, kdf, random);
      List<Admin> next = new ArrayList<>(admins);
      next.add(
          new Admin(
              id,
              name,
              ImmutableBytes.copyOf(slot.encode()),
              ImmutableBytes.EMPTY,
              0,
              clock.instant(),
              expires));
      persist(next);
    }
  }

  /**
   * Creates a setup-state administrator with a generated initial password, written owner-only to
   * {@link #initialPasswordFile()} (ADR 0021). The file is deleted when no administrator remains in
   * setup state.
   */
  public synchronized void createForSetupWithGeneratedPassword(String name, Instant expires)
      throws AdminException,
          IOException,
          CryptoException,
          KdfAdmission.Rejected,
          InterruptedException {
    // 24 characters from a 32-symbol alphabet: 120 bits, no ambiguous characters.
    char[] alphabet = "abcdefghjkmnpqrstuvwxyz23456789-".toCharArray();
    char[] password = new char[24];
    byte[] encoded = new byte[password.length + 1];
    try {
      for (int i = 0; i < password.length; i++) {
        password[i] = alphabet[random.nextInt(alphabet.length)];
        encoded[i] = (byte) password[i];
      }
      encoded[password.length] = '\n';
      CharSequence chars = java.nio.CharBuffer.wrap(password);
      validateNew(name, chars);
      DurableFiles.createPrivateDirectories(java.util.Objects.requireNonNull(file.getParent()));
      DurableFiles.writeAtomically(initialPasswordFile(), encoded);
      try {
        createForSetup(name, chars, expires);
      } catch (AdminException
          | IOException
          | CryptoException
          | KdfAdmission.Rejected
          | InterruptedException
          | RuntimeException e) {
        DurableFiles.deleteDurably(initialPasswordFile());
        throw e;
      }
    } finally {
      java.util.Arrays.fill(password, '\0');
      java.util.Arrays.fill(encoded, (byte) 0);
    }
  }

  /**
   * Creates an administrator and returns the TOTP secret to enroll in an authenticator app (the
   * caller shows it once and closes it).
   */
  public synchronized Secret create(String name, CharSequence password)
      throws AdminException,
          IOException,
          CryptoException,
          KdfAdmission.Rejected,
          InterruptedException {
    validateNew(name, password);
    OpaqueId id = ids.next();
    Secret totp = Totp.generateSecret(random);
    try (SymmetricKey key = SymmetricKey.generate(random);
        Secret credential = Secret.utf8(password)) {
      KeySlot slot =
          KeySlot.create(
              id, ids.next(), SlotKind.PASSWORD, credential, key, parameters, kdf, random);
      byte[] sealed = key.wrap(totp, context(id));
      List<Admin> next = new ArrayList<>(admins);
      next.add(
          new Admin(
              id,
              name,
              ImmutableBytes.copyOf(slot.encode()),
              ImmutableBytes.copyOf(sealed),
              0,
              clock.instant(),
              null));
      persist(next);
      return totp;
    } catch (IOException | CryptoException | KdfAdmission.Rejected | InterruptedException e) {
      totp.close();
      throw e;
    }
  }

  private void validateNew(String name, CharSequence password) throws AdminException {
    if (!NAME.matcher(name).matches()) {
      throw new AdminException("name must be 1-32 lower-case letters, digits, '.', '_' or '-'");
    }
    validatePassword(password);
    if (admins.stream().anyMatch(a -> a.name().equals(name))) {
      throw new AdminException("an administrator with that name exists");
    }
    if (admins.size() >= MAX_ADMINS) {
      throw new AdminException("too many administrators");
    }
  }

  private static void validatePassword(CharSequence password) throws AdminException {
    if (password.length() < 14 || password.length() > 1024) {
      throw new AdminException("admin passwords need at least 14 characters");
    }
  }

  public synchronized void delete(String name) throws AdminException, IOException {
    List<Admin> next = new ArrayList<>(admins);
    if (!next.removeIf(a -> a.name().equals(name))) {
      throw new AdminException("no such administrator");
    }
    persist(next);
  }

  /**
   * Checks an admin password. Unknown names cost the same Argon2id work as known ones and give the
   * same empty result as a wrong password.
   */
  public Optional<Verified> verifyPassword(String name, CharSequence password)
      throws KdfAdmission.Rejected, InterruptedException {
    Admin admin;
    synchronized (this) {
      admin = admins.stream().filter(a -> a.name().equals(name)).findFirst().orElse(null);
    }
    try (Secret credential = Secret.utf8(password)) {
      if (admin == null) {
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        try {
          kdf.derive(credential, salt, parameters).close();
        } catch (CryptoException e) {
          // Dummy work only; the result is discarded either way.
        }
        return Optional.empty();
      }
      SymmetricKey key;
      try {
        KeySlot slot = KeySlot.decode(admin.slot().toByteArray(), kdf.limits());
        key = slot.unwrap(credential, kdf);
      } catch (CryptoException | FormatException e) {
        return Optional.empty();
      }
      Instant setupExpires = admin.setupExpires();
      if (setupExpires != null && !clock.instant().isBefore(setupExpires)) {
        // An expired initial password is refused like a wrong one (ADR 0021).
        key.close();
        return Optional.empty();
      }
      return Optional.of(new Verified(admin.id(), admin.name(), key, setupExpires != null));
    }
  }

  /** Checks a TOTP code for a verified admin and records the step so it can never be reused. */
  public synchronized boolean verifyTotp(Verified verified, String code)
      throws CryptoException, IOException {
    for (int i = 0; i < admins.size(); i++) {
      Admin admin = admins.get(i);
      if (!admin.id().equals(verified.id)) {
        continue;
      }
      if (admin.inSetup()) {
        return false;
      }
      OptionalLong step;
      try (Secret secret =
          verified.key.open(admin.sealedTotp().toByteArray(), context(admin.id()))) {
        step = Totp.verify(secret, code, clock.instant(), admin.totpStep());
      }
      if (step.isEmpty()) {
        return false;
      }
      List<Admin> next = new ArrayList<>(admins);
      next.set(
          i,
          new Admin(
              admin.id(),
              admin.name(),
              admin.slot(),
              admin.sealedTotp(),
              step.getAsLong(),
              admin.created(),
              null));
      persist(next);
      return true;
    }
    return false;
  }

  /** Outcome of {@link #completeSetup}. */
  public enum SetupResult {
    /** Password replaced and TOTP enrolled; the administrator is active. */
    COMPLETED,
    /** The TOTP code did not match the offered secret. Nothing changed. */
    WRONG_CODE
  }

  /**
   * Completes first-login setup (ADR 0021) for an administrator verified with its initial password:
   * checks {@code code} against {@code totpSecret} (the secret the caller showed the
   * administrator), then replaces the bootstrap slot with a password slot under {@code newPassword}
   * wrapping a fresh admin key, seals the TOTP secret under that key, and records the accepted step
   * so the code cannot be replayed at the next login.
   *
   * @throws AdminException if the administrator is not in (unexpired) setup state, or the new
   *     password is too short or equal to the initial one
   */
  public synchronized SetupResult completeSetup(
      Verified verified, CharSequence newPassword, Secret totpSecret, String code)
      throws AdminException,
          IOException,
          CryptoException,
          KdfAdmission.Rejected,
          InterruptedException {
    int index = -1;
    for (int i = 0; i < admins.size(); i++) {
      if (admins.get(i).id().equals(verified.id)) {
        index = i;
      }
    }
    if (index < 0) {
      throw new AdminException("no such administrator");
    }
    Admin admin = admins.get(index);
    Instant setupExpires = admin.setupExpires();
    if (setupExpires == null || !clock.instant().isBefore(setupExpires)) {
      throw new AdminException("setup is not pending");
    }
    validatePassword(newPassword);
    OptionalLong step = Totp.verify(totpSecret, code, clock.instant(), 0);
    if (step.isEmpty()) {
      return SetupResult.WRONG_CODE;
    }
    try (Secret credential = Secret.utf8(newPassword)) {
      KeySlot old;
      try {
        old = KeySlot.decode(admin.slot().toByteArray(), kdf.limits());
      } catch (FormatException e) {
        throw new CryptoException("admin slot unreadable", e);
      }
      try {
        old.unwrap(credential, kdf).close();
        throw new AdminException("choose a password different from the initial one");
      } catch (CryptoException e) {
        // Expected: the new password does not open the bootstrap slot.
      }
      try (SymmetricKey key = SymmetricKey.generate(random)) {
        KeySlot slot =
            KeySlot.create(
                admin.id(),
                ids.next(),
                SlotKind.PASSWORD,
                credential,
                key,
                parameters,
                kdf,
                random);
        byte[] sealed = key.wrap(totpSecret, context(admin.id()));
        List<Admin> next = new ArrayList<>(admins);
        next.set(
            index,
            new Admin(
                admin.id(),
                admin.name(),
                ImmutableBytes.copyOf(slot.encode()),
                ImmutableBytes.copyOf(sealed),
                step.getAsLong(),
                admin.created(),
                null));
        persist(next);
      }
    }
    return SetupResult.COMPLETED;
  }

  private void persist(List<Admin> next) throws IOException {
    DurableFiles.createPrivateDirectories(java.util.Objects.requireNonNull(file.getParent()));
    DurableFiles.writeAtomically(file, encode(next));
    admins.clear();
    admins.addAll(next);
    if (next.stream().noneMatch(Admin::inSetup)) {
      DurableFiles.deleteDurably(initialPasswordFile());
    }
  }

  private static AssociatedData context(OpaqueId adminId) {
    return AssociatedData.builder(Purpose.ADMIN_FACTOR, FACTOR_CONTEXT_VERSION)
        .id("admin", adminId)
        .build();
  }

  private static byte[] encode(List<Admin> list) {
    int version = list.stream().anyMatch(Admin::inSetup) ? VERSION_2 : VERSION_1;
    RecordWriter w = new RecordWriter().raw(MAGIC).u8(version).u16(list.size());
    for (Admin a : list) {
      w.id(a.id())
          .string(a.name())
          .bytes(a.slot().toByteArray())
          .bytes(a.sealedTotp().toByteArray())
          .i64(a.totpStep())
          .i64(a.created().getEpochSecond());
      if (version == VERSION_2) {
        Instant setupExpires = a.setupExpires();
        w.u8(setupExpires == null ? STATE_ACTIVE : STATE_SETUP)
            .i64(setupExpires == null ? 0 : setupExpires.getEpochSecond());
      }
    }
    return w.toByteArray();
  }

  private static List<Admin> decode(byte[] data) throws FormatException {
    RecordReader r = new RecordReader(data);
    if (!java.util.Arrays.equals(r.raw(4), MAGIC)) {
      throw new FormatException("not an admin store");
    }
    int version = r.u8();
    if (version != VERSION_1 && version != VERSION_2) {
      throw new FormatException("unsupported admin store version " + version);
    }
    int count = r.u16();
    if (count > MAX_ADMINS) {
      throw new FormatException("too many administrators");
    }
    List<Admin> list = new ArrayList<>();
    for (int i = 0; i < count; i++) {
      OpaqueId id = r.id();
      String name = r.string(64);
      ImmutableBytes slot = ImmutableBytes.copyOf(r.bytes(4096));
      ImmutableBytes sealedTotp = ImmutableBytes.copyOf(r.bytes(4096));
      long totpStep = r.i64();
      Instant created = Instant.ofEpochSecond(r.i64());
      Instant setupExpires = null;
      if (version == VERSION_2) {
        int state = r.u8();
        long expires = r.i64();
        if (state == STATE_SETUP) {
          setupExpires = Instant.ofEpochSecond(expires);
        } else if (state != STATE_ACTIVE || expires != 0) {
          throw new FormatException("invalid administrator state");
        }
      }
      if ((setupExpires == null) == (sealedTotp.length() == 0)) {
        throw new FormatException("administrator state does not match its factor");
      }
      list.add(new Admin(id, name, slot, sealedTotp, totpStep, created, setupExpires));
    }
    r.expectEnd();
    return list;
  }
}
