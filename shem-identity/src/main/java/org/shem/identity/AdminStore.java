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
 */
public final class AdminStore {
  private static final byte[] MAGIC = {'S', 'H', 'A', 'D'};
  private static final int VERSION = 1;
  private static final int MAX_ADMINS = 32;
  private static final Pattern NAME = Pattern.compile("[a-z0-9][a-z0-9._-]{0,31}");

  /** A failed administration change; messages are safe to show. */
  public static final class AdminException extends Exception {
    private static final long serialVersionUID = 1L;

    public AdminException(String message) {
      super(message);
    }
  }

  private record Admin(
      OpaqueId id,
      String name,
      ImmutableBytes slot,
      ImmutableBytes sealedTotp,
      long totpStep,
      Instant created) {}

  /** A password-verified administrator; holds the admin key until closed. */
  public static final class Verified implements AutoCloseable {
    private final OpaqueId id;
    private final String name;
    private final SymmetricKey key;

    private Verified(OpaqueId id, String name, SymmetricKey key) {
      this.id = id;
      this.name = name;
      this.key = key;
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
    if (!NAME.matcher(name).matches()) {
      throw new AdminException("name must be 1-32 lower-case letters, digits, '.', '_' or '-'");
    }
    if (password.length() < 14 || password.length() > 1024) {
      throw new AdminException("admin passwords need at least 14 characters");
    }
    if (admins.stream().anyMatch(a -> a.name().equals(name))) {
      throw new AdminException("an administrator with that name exists");
    }
    if (admins.size() >= MAX_ADMINS) {
      throw new AdminException("too many administrators");
    }
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
              clock.instant()));
      persist(next);
      return totp;
    } catch (IOException | CryptoException | KdfAdmission.Rejected | InterruptedException e) {
      totp.close();
      throw e;
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
      try {
        KeySlot slot = KeySlot.decode(admin.slot().toByteArray(), kdf.limits());
        return Optional.of(new Verified(admin.id(), admin.name(), slot.unwrap(credential, kdf)));
      } catch (CryptoException | FormatException e) {
        return Optional.empty();
      }
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
              admin.created()));
      persist(next);
      return true;
    }
    return false;
  }

  private void persist(List<Admin> next) throws IOException {
    DurableFiles.createPrivateDirectories(java.util.Objects.requireNonNull(file.getParent()));
    DurableFiles.writeAtomically(file, encode(next));
    admins.clear();
    admins.addAll(next);
  }

  private static AssociatedData context(OpaqueId adminId) {
    return AssociatedData.builder(Purpose.ADMIN_FACTOR, VERSION).id("admin", adminId).build();
  }

  private static byte[] encode(List<Admin> list) {
    RecordWriter w = new RecordWriter().raw(MAGIC).u8(VERSION).u16(list.size());
    for (Admin a : list) {
      w.id(a.id())
          .string(a.name())
          .bytes(a.slot().toByteArray())
          .bytes(a.sealedTotp().toByteArray())
          .i64(a.totpStep())
          .i64(a.created().getEpochSecond());
    }
    return w.toByteArray();
  }

  private static List<Admin> decode(byte[] data) throws FormatException {
    RecordReader r = new RecordReader(data);
    if (!java.util.Arrays.equals(r.raw(4), MAGIC) || r.u8() != VERSION) {
      throw new FormatException("not an admin store");
    }
    int count = r.u16();
    if (count > MAX_ADMINS) {
      throw new FormatException("too many administrators");
    }
    List<Admin> list = new ArrayList<>();
    for (int i = 0; i < count; i++) {
      list.add(
          new Admin(
              r.id(),
              r.string(64),
              ImmutableBytes.copyOf(r.bytes(4096)),
              ImmutableBytes.copyOf(r.bytes(4096)),
              r.i64(),
              Instant.ofEpochSecond(r.i64())));
    }
    r.expectEnd();
    return list;
  }
}
