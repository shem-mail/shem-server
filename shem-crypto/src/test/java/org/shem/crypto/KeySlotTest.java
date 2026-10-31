package org.shem.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.shem.common.FormatException;
import org.shem.common.OpaqueId;

class KeySlotTest {
  private final Argon2idKdf kdf = TestKeys.kdf();
  private final OpaqueId mailbox = TestKeys.id();

  private KeySlot slot(String password, SymmetricKey master) throws Exception {
    try (Secret credential = Secret.utf8(password)) {
      return KeySlot.create(
          mailbox,
          TestKeys.id(),
          SlotKind.PASSWORD,
          credential,
          master,
          TestKeys.CHEAP,
          kdf,
          TestKeys.RANDOM);
    }
  }

  @Test
  void correctCredentialUnwrapsMasterKey() throws Exception {
    try (SymmetricKey master = SymmetricKey.generate(TestKeys.RANDOM)) {
      KeySlot decoded =
          KeySlot.decode(slot("correct horse", master).encode(), TestKeys.TEST_LIMITS);
      try (Secret credential = Secret.utf8("correct horse");
          SymmetricKey unwrapped = decoded.unwrap(credential, kdf)) {
        assertThat(unwrapped.secret().contentEquals(master.secret())).isTrue();
      }
    }
  }

  @Test
  void wrongCredentialFailsAuthentication() throws Exception {
    try (SymmetricKey master = SymmetricKey.generate(TestKeys.RANDOM);
        Secret wrong = Secret.utf8("battery staple")) {
      KeySlot slot = slot("correct horse", master);
      assertThatThrownBy(() -> slot.unwrap(wrong, kdf)).isInstanceOf(CryptoException.class);
    }
  }

  @Test
  void tamperedParametersOrKindFailAuthentication() throws Exception {
    try (SymmetricKey master = SymmetricKey.generate(TestKeys.RANDOM);
        Secret credential = Secret.utf8("correct horse")) {
      byte[] encoded = slot("correct horse", master).encode();
      // Byte offsets: magic 4, format 1, profile 1, mailbox 16, slot 16, kind 1, memory u32.
      int kindOffset = 4 + 2 + 32;
      byte[] kindChanged = encoded.clone();
      kindChanged[kindOffset] = (byte) SlotKind.APP.code();
      KeySlot relabelled = KeySlot.decode(kindChanged, TestKeys.TEST_LIMITS);
      assertThatThrownBy(() -> relabelled.unwrap(credential, kdf))
          .isInstanceOf(CryptoException.class);

      byte[] iterationsChanged = encoded.clone();
      iterationsChanged[kindOffset + 1 + 4 + 3] = 2;
      KeySlot weakened = KeySlot.decode(iterationsChanged, TestKeys.TEST_LIMITS);
      assertThatThrownBy(() -> weakened.unwrap(credential, kdf))
          .isInstanceOf(CryptoException.class);
    }
  }

  @Test
  void excessiveStoredParametersAreRejectedBeforeDerivation() throws Exception {
    try (SymmetricKey master = SymmetricKey.generate(TestKeys.RANDOM)) {
      byte[] encoded = slot("pw", master).encode();
      int memoryOffset = 4 + 2 + 32 + 1;
      encoded[memoryOffset] = 0x7f; // ~2 TiB
      assertThatThrownBy(() -> KeySlot.decode(encoded, Argon2Parameters.Limits.DEFAULT))
          .isInstanceOf(FormatException.class);
    }
  }

  @Test
  void truncatedSlotIsCorruption() throws Exception {
    try (SymmetricKey master = SymmetricKey.generate(TestKeys.RANDOM)) {
      byte[] encoded = slot("pw", master).encode();
      byte[] truncated = java.util.Arrays.copyOf(encoded, encoded.length - 1);
      assertThatThrownBy(() -> KeySlot.decode(truncated, TestKeys.TEST_LIMITS))
          .isInstanceOf(FormatException.class);
    }
  }

  @Test
  void admissionRejectsWorkBeyondBudget() throws Exception {
    KdfAdmission admission = new KdfAdmission(100, Duration.ofMillis(50));
    try (KdfAdmission.Permit held = admission.acquire(TestKeys.CHEAP)) {
      assertThat(held).isNotNull();
      assertThat(admission.availableKiB()).isEqualTo(36);
      assertThatThrownBy(() -> admission.acquire(TestKeys.CHEAP))
          .isInstanceOf(KdfAdmission.Rejected.class);
    }
    assertThat(admission.availableKiB()).isEqualTo(100);
    assertThatThrownBy(() -> admission.acquire(new Argon2Parameters(1024, 1, 1)))
        .isInstanceOf(KdfAdmission.Rejected.class);
  }
}
