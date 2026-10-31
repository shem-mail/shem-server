package org.shem.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.shem.common.FormatException;
import org.shem.common.OpaqueId;

class KeyringTest {
  private final OpaqueId mailbox = TestKeys.id();

  private Keyring fresh() throws Exception {
    return Keyring.create(
        mailbox, MailboxPrivateKey.generate(1), SymmetricKey.generate(TestKeys.RANDOM), 1);
  }

  @Test
  void sealsAndOpensWithSlotsAndRetainedVersions() throws Exception {
    try (SymmetricKey master = SymmetricKey.generate(TestKeys.RANDOM);
        Keyring initial = fresh();
        Keyring withSlot =
            initial.withSlotAdded(
                new SlotDescriptor(TestKeys.id(), SlotKind.APP, "phone", Instant.EPOCH));
        Keyring rotated =
            withSlot.withRotatedKeys(
                MailboxPrivateKey.generate(2), SymmetricKey.generate(TestKeys.RANDOM), 2);
        Keyring opened = Keyring.open(rotated.seal(master), mailbox, master)) {
      assertThat(opened.generation()).isEqualTo(3);
      assertThat(opened.currentPublicKey()).isEqualTo(rotated.currentPublicKey());
      assertThat(opened.privateKey(1)).isPresent();
      assertThat(opened.dataVersions()).containsExactly(1, 2);
      assertThat(opened.slots()).extracting(SlotDescriptor::label).containsExactly("phone");
      try (Keyring retired =
          opened.withRetiredVersions(java.util.List.of(1), java.util.List.of(1))) {
        assertThat(retired.privateKey(1)).isEmpty();
        assertThat(retired.dataVersions()).containsExactly(2);
      }
    }
  }

  @Test
  void rejectsWrongMasterKeyOtherMailboxAndTampering() throws Exception {
    try (SymmetricKey master = SymmetricKey.generate(TestKeys.RANDOM);
        SymmetricKey other = SymmetricKey.generate(TestKeys.RANDOM);
        Keyring keyring = fresh()) {
      byte[] sealed = keyring.seal(master);
      assertThatThrownBy(() -> Keyring.open(sealed, mailbox, other))
          .isInstanceOf(CryptoException.class);
      assertThatThrownBy(() -> Keyring.open(sealed, TestKeys.id(), master))
          .isInstanceOf(FormatException.class);
      byte[] generationBumped = sealed.clone();
      generationBumped[4 + 2 + 16 + 7] ^= 1;
      assertThatThrownBy(() -> Keyring.open(generationBumped, mailbox, master))
          .isInstanceOf(CryptoException.class);
    }
  }

  @Test
  void rotationVersionsMustIncrease() throws Exception {
    try (Keyring keyring = fresh();
        MailboxPrivateKey stale = MailboxPrivateKey.generate(1);
        SymmetricKey root = SymmetricKey.generate(TestKeys.RANDOM)) {
      assertThatThrownBy(() -> keyring.withRotatedKeys(stale, root, 2))
          .isInstanceOf(IllegalArgumentException.class);
    }
  }
}
