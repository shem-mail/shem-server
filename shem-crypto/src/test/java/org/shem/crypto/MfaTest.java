package org.shem.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import org.junit.jupiter.api.Test;
import org.shem.common.OpaqueId;

class MfaTest {
  private static Secret rfcSecret() {
    return Secret.wrap("12345678901234567890".getBytes(StandardCharsets.US_ASCII));
  }

  @Test
  void totpMatchesRfc6238Vectors() throws Exception {
    try (Secret secret = rfcSecret()) {
      // RFC 6238 appendix B (SHA-1), truncated to six digits.
      assertThat(Totp.code(secret, 59 / 30)).isEqualTo("287082");
      assertThat(Totp.code(secret, 1111111109L / 30)).isEqualTo("081804");
      assertThat(Totp.code(secret, 1234567890L / 30)).isEqualTo("005924");
      assertThat(Totp.code(secret, 2000000000L / 30)).isEqualTo("279037");
      assertThat(Totp.base32(secret)).isEqualTo("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    }
  }

  @Test
  void totpAllowsOneStepOfDriftAndRejectsReplay() throws Exception {
    try (Secret secret = rfcSecret()) {
      Instant now = Instant.ofEpochSecond(1234567890L);
      long step = 1234567890L / 30;
      assertThat(Totp.verify(secret, "005924", now, 0)).hasValue(step);
      assertThat(Totp.verify(secret, "005924", now, step)).as("same step again").isEmpty();
      assertThat(Totp.verify(secret, Totp.code(secret, step - 1), now, 0)).hasValue(step - 1);
      assertThat(Totp.verify(secret, Totp.code(secret, step + 1), now, 0)).hasValue(step + 1);
      assertThat(Totp.verify(secret, Totp.code(secret, step + 2), now, 0)).isEmpty();
      assertThat(Totp.verify(secret, "00592", now, 0)).isEmpty();
      assertThat(Totp.verify(secret, "00592x", now, 0)).isEmpty();
    }
  }

  private static MfaFactor factor(String label) {
    return new MfaFactor(
        OpaqueId.random(TestKeys.RANDOM),
        MfaFactor.Kind.TOTP,
        label,
        Instant.ofEpochSecond(1_790_000_000L),
        7,
        Totp.generateSecret(TestKeys.RANDOM));
  }

  @Test
  void factorsAreSealedAndSurviveEveryKeyringTransition() throws Exception {
    OpaqueId mailbox = TestKeys.id();
    try (SymmetricKey master = SymmetricKey.generate(TestKeys.RANDOM);
        Keyring base =
            Keyring.create(
                mailbox, MailboxPrivateKey.generate(1), SymmetricKey.generate(TestKeys.RANDOM), 1);
        Keyring withFactor = base.withFactors(List.of(factor("phone")));
        Keyring rotated =
            withFactor
                .withSlots(List.of())
                .withRotatedKeys(
                    MailboxPrivateKey.generate(2), SymmetricKey.generate(TestKeys.RANDOM), 2);
        Keyring reopened = Keyring.open(rotated.seal(master), mailbox, master)) {
      assertThat(reopened.factors()).hasSize(1);
      MfaFactor stored = reopened.factors().getFirst();
      assertThat(stored.label()).isEqualTo("phone");
      assertThat(stored.counter()).isEqualTo(7);
      assertThat(stored.material().bytes())
          .isEqualTo(withFactor.factors().getFirst().material().bytes());
      byte[] sealed = rotated.seal(master);
      assertThat(new String(sealed, StandardCharsets.ISO_8859_1)).doesNotContain("phone");
    }
  }

  @Test
  void formatOneKeyringsStillOpenAndDowngradesFail() throws Exception {
    byte[] fixture;
    try (InputStream in =
        Objects.requireNonNull(MfaTest.class.getResourceAsStream("keyring-format1.bin"))) {
      fixture = in.readAllBytes();
    }
    byte[] masterBytes = new byte[32];
    byte[] mailboxBytes = new byte[16];
    for (int i = 0; i < 32; i++) {
      masterBytes[i] = (byte) i;
    }
    for (int i = 0; i < 16; i++) {
      mailboxBytes[i] = (byte) (0x10 + i);
    }
    OpaqueId mailbox = OpaqueId.fromBytes(mailboxBytes);
    try (SymmetricKey master = SymmetricKey.of(Secret.wrap(masterBytes));
        Keyring old = Keyring.open(fixture, mailbox, master)) {
      assertThat(old.factors()).isEmpty();
      assertThat(old.slots()).extracting(SlotDescriptor::label).containsExactly("password");
      assertThat(old.currentPublicKey().fingerprint())
          .isEqualTo("17d3c56d5ccfddaa66f317564fd0eedf");
      try (Keyring upgraded = old.withFactors(List.of(factor("key")))) {
        byte[] sealed = upgraded.seal(master);
        assertThat(sealed[4]).as("written as format 2").isEqualTo((byte) 2);
        sealed[4] = 1;
        assertThatThrownBy(() -> Keyring.open(sealed, mailbox, master))
            .as("format byte is authenticated")
            .isInstanceOf(CryptoException.class);
      }
    }
  }
}
