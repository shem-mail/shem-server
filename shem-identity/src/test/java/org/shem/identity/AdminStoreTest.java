package org.shem.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
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

  private AdminStore open() throws Exception {
    return AdminStore.open(
        dir.resolve("admin/admins.bin"),
        new Argon2idKdf(
            new KdfAdmission(1 << 20, Duration.ofSeconds(5)),
            new Argon2Parameters.Limits(8, 1 << 20, 10, 8)),
        new Argon2Parameters(64, 1, 1),
        IdGenerator.secure(RANDOM),
        RANDOM,
        Clock.systemUTC());
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
}
