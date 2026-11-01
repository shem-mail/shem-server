package org.shem.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.shem.common.IdGenerator;
import org.shem.crypto.Argon2Parameters;
import org.shem.crypto.Argon2idKdf;
import org.shem.crypto.KdfAdmission;
import org.shem.crypto.Secret;
import org.shem.crypto.Totp;

class AdminStoreTest {
  private static final SecureRandom RANDOM = new SecureRandom();
  private static final String PASSWORD = "operator passphrase 2026";
  @TempDir Path dir;

  /** A clock tests can move forward. */
  private static final class MutableClock extends Clock {
    private Instant now = Instant.now();

    @Override
    public java.time.ZoneId getZone() {
      return java.time.ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(java.time.ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      return now;
    }

    void advance(Duration d) {
      now = now.plus(d);
    }
  }

  private final MutableClock clock = new MutableClock();

  private AdminStore open() throws Exception {
    return open(Clock.systemUTC());
  }

  private AdminStore open(Clock at) throws Exception {
    return AdminStore.open(
        dir.resolve("admin/admins.bin"),
        new Argon2idKdf(
            new KdfAdmission(1 << 20, Duration.ofSeconds(5)),
            new Argon2Parameters.Limits(8, 1 << 20, 10, 8)),
        new Argon2Parameters(64, 1, 1),
        IdGenerator.secure(RANDOM),
        RANDOM,
        at);
  }

  private String currentCode(Secret totp) throws Exception {
    return Totp.code(totp, clock.instant().getEpochSecond() / Totp.STEP_SECONDS);
  }

  @Test
  void adminsNeedPasswordAndTotpAndTheFileRevealsNeither() throws Exception {
    AdminStore store = open();
    String base32;
    Secret totp = store.create("ops", PASSWORD);
    base32 = Totp.base32(totp);
    assertThatThrownBy(() -> store.create("ops", PASSWORD)).hasMessageContaining("exists");
    assertThatThrownBy(() -> store.create("Bad Name", PASSWORD)).hasMessageContaining("name");
    assertThatThrownBy(() -> store.create("short", "too short")).hasMessageContaining("14");

    AdminStore reopened = open();
    assertThat(reopened.names()).containsExactly("ops");
    assertThat(reopened.verifyPassword("ops", "wrong passphrase!!")).isEmpty();
    assertThat(reopened.verifyPassword("nobody", PASSWORD)).isEmpty();
    try (AdminStore.Verified verified = reopened.verifyPassword("ops", PASSWORD).orElseThrow()) {
      long step = java.time.Instant.now().getEpochSecond() / Totp.STEP_SECONDS;
      String code = Totp.code(totp, step);
      assertThat(reopened.verifyTotp(verified, "000000".equals(code) ? "111111" : "000000"))
          .isFalse();
      assertThat(reopened.verifyTotp(verified, code)).isTrue();
      assertThat(reopened.verifyTotp(verified, code)).as("replay").isFalse();
      AdminStore restarted = open();
      try (AdminStore.Verified again = restarted.verifyPassword("ops", PASSWORD).orElseThrow()) {
        assertThat(restarted.verifyTotp(again, code)).as("replay after restart").isFalse();
      }
    }
    byte[] file = Files.readAllBytes(dir.resolve("admin/admins.bin"));
    String text = new String(file, StandardCharsets.ISO_8859_1);
    assertThat(text).doesNotContain(PASSWORD).doesNotContain(base32);
    totp.close();

    reopened.delete("ops");
    assertThat(open().isEmpty()).isTrue();
    assertThatThrownBy(() -> reopened.delete("ops")).hasMessageContaining("no such");
  }

  @Test
  void setupAdministratorMustReplacePasswordAndEnrollTotpBeforeLoggingIn() throws Exception {
    String initial = "initial bootstrap passphrase";
    String chosen = "the operator's own passphrase";
    AdminStore store = open(clock);
    store.createForSetup("admin", initial, clock.instant().plus(Duration.ofDays(3)));
    assertThat(store.namesPendingSetup()).containsExactly("admin");
    assertThat(Files.readAllBytes(dir.resolve("admin/admins.bin"))[4])
        .as("setup state needs format version 2")
        .isEqualTo((byte) 2);

    AdminStore reopened = open(clock);
    try (Secret totp = Totp.generateSecret(RANDOM);
        AdminStore.Verified verified = reopened.verifyPassword("admin", initial).orElseThrow()) {
      assertThat(verified.setupRequired()).isTrue();
      assertThat(reopened.verifyTotp(verified, currentCode(totp)))
          .as("no TOTP login before setup")
          .isFalse();
      String wrong = "000000".equals(currentCode(totp)) ? "111111" : "000000";
      assertThat(reopened.completeSetup(verified, chosen, totp, wrong))
          .isEqualTo(AdminStore.SetupResult.WRONG_CODE);
      assertThatThrownBy(() -> reopened.completeSetup(verified, "short", totp, currentCode(totp)))
          .hasMessageContaining("14");
      assertThatThrownBy(() -> reopened.completeSetup(verified, initial, totp, currentCode(totp)))
          .hasMessageContaining("different");
      assertThat(reopened.namesPendingSetup()).as("failed attempts change nothing").hasSize(1);

      String code = currentCode(totp);
      assertThat(reopened.completeSetup(verified, chosen, totp, code))
          .isEqualTo(AdminStore.SetupResult.COMPLETED);
      assertThatThrownBy(() -> reopened.completeSetup(verified, chosen, totp, code))
          .hasMessageContaining("not pending");

      AdminStore restarted = open(clock);
      assertThat(restarted.namesPendingSetup()).isEmpty();
      assertThat(Files.readAllBytes(dir.resolve("admin/admins.bin"))[4])
          .as("back to version 1 once every administrator is active")
          .isEqualTo((byte) 1);
      assertThat(restarted.verifyPassword("admin", initial)).as("initial password gone").isEmpty();
      try (AdminStore.Verified again = restarted.verifyPassword("admin", chosen).orElseThrow()) {
        assertThat(again.setupRequired()).isFalse();
        assertThat(restarted.verifyTotp(again, code)).as("setup code cannot be replayed").isFalse();
        clock.advance(Duration.ofSeconds(Totp.STEP_SECONDS));
        assertThat(restarted.verifyTotp(again, currentCode(totp))).isTrue();
      }
      String text =
          new String(
              Files.readAllBytes(dir.resolve("admin/admins.bin")), StandardCharsets.ISO_8859_1);
      assertThat(text)
          .doesNotContain(initial)
          .doesNotContain(chosen)
          .doesNotContain(Totp.base32(totp));
    }
  }

  @Test
  void initialPasswordExpires() throws Exception {
    String initial = "initial bootstrap passphrase";
    AdminStore store = open(clock);
    store.createForSetup("admin", initial, clock.instant().plus(Duration.ofDays(3)));
    try (Secret totp = Totp.generateSecret(RANDOM);
        AdminStore.Verified verified = store.verifyPassword("admin", initial).orElseThrow()) {
      clock.advance(Duration.ofDays(3));
      assertThat(store.verifyPassword("admin", initial)).isEmpty();
      assertThatThrownBy(
              () ->
                  store.completeSetup(verified, "a different passphrase", totp, currentCode(totp)))
          .as("a login started before expiry cannot finish after it")
          .hasMessageContaining("not pending");
    }
    assertThatThrownBy(() -> store.createForSetup("late", initial, clock.instant()))
        .hasMessageContaining("future");
  }

  @Test
  void generatedInitialPasswordIsOwnerOnlyAndRemovedAfterSetup() throws Exception {
    AdminStore store = open(clock);
    store.createForSetupWithGeneratedPassword("admin", clock.instant().plus(Duration.ofDays(1)));
    Path file = store.initialPasswordFile();
    assertThat(file).isEqualTo(dir.resolve("admin/initial-password"));
    assertThat(
            java.nio.file.attribute.PosixFilePermissions.toString(
                Files.getPosixFilePermissions(file)))
        .isEqualTo("rw-------");
    String password = Files.readString(file, StandardCharsets.US_ASCII).strip();
    assertThat(password).matches("[a-z2-9-]{24}");
    String store1 =
        new String(
            Files.readAllBytes(dir.resolve("admin/admins.bin")), StandardCharsets.ISO_8859_1);
    assertThat(store1).doesNotContain(password);

    try (Secret totp = Totp.generateSecret(RANDOM);
        AdminStore.Verified verified = store.verifyPassword("admin", password).orElseThrow()) {
      assertThat(
              store.completeSetup(
                  verified, "the operator's own passphrase", totp, currentCode(totp)))
          .isEqualTo(AdminStore.SetupResult.COMPLETED);
    }
    assertThat(file).doesNotExist();
  }

  @Test
  void deletingThePendingAdministratorRemovesTheInitialPasswordFile() throws Exception {
    AdminStore store = open(clock);
    store.createForSetupWithGeneratedPassword("admin", clock.instant().plus(Duration.ofDays(1)));
    store.delete("admin");
    assertThat(store.initialPasswordFile()).doesNotExist();
  }

  @Test
  void versionOneFilesStayReadableAndUnknownVersionsAreRejected() throws Exception {
    Path file = dir.resolve("admin/admins.bin");
    try (Secret totp = open().create("ops", PASSWORD)) {
      byte[] v1 = Files.readAllBytes(file);
      assertThat(v1[4]).isEqualTo((byte) 1);
      try (AdminStore.Verified v = open().verifyPassword("ops", PASSWORD).orElseThrow()) {
        assertThat(v.setupRequired()).isFalse();
      }
      v1[4] = 9;
      Files.write(file, v1);
      assertThatThrownBy(this::open).hasMessageContaining("version");
      assertThat(totp.isClosed()).isFalse();
    }
  }
}
