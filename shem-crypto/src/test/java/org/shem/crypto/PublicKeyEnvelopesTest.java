package org.shem.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class PublicKeyEnvelopesTest {
  private final AssociatedData context =
      AssociatedData.builder(Purpose.CONTENT_KEY_ENVELOPE, 1).id("blob", TestKeys.id()).build();

  @Test
  void roundTripsWithMatchingKeyAndContext() throws Exception {
    try (MailboxPrivateKey key = MailboxPrivateKey.generate(1);
        SymmetricKey content = SymmetricKey.generate(TestKeys.RANDOM)) {
      byte[] envelope = PublicKeyEnvelopes.sealKey(key.publicKey(), context, content);
      try (SymmetricKey opened = PublicKeyEnvelopes.openKey(key, context, envelope)) {
        assertThat(opened.secret().contentEquals(content.secret())).isTrue();
      }
      assertThat(PublicKeyEnvelopes.keyVersionOf(envelope)).isEqualTo(1);
    }
  }

  @Test
  void rejectsWrongPrivateKey() throws Exception {
    try (MailboxPrivateKey key = MailboxPrivateKey.generate(1);
        MailboxPrivateKey other = MailboxPrivateKey.generate(1);
        Secret payload = Secret.random(TestKeys.RANDOM, 32)) {
      byte[] envelope = PublicKeyEnvelopes.seal(key.publicKey(), context, payload);
      assertThatThrownBy(() -> PublicKeyEnvelopes.open(other, context, envelope))
          .isInstanceOf(CryptoException.class);
    }
  }

  @Test
  void rejectsSubstitutedContext() throws Exception {
    try (MailboxPrivateKey key = MailboxPrivateKey.generate(1);
        Secret payload = Secret.random(TestKeys.RANDOM, 32)) {
      byte[] envelope = PublicKeyEnvelopes.seal(key.publicKey(), context, payload);
      AssociatedData otherBlob =
          AssociatedData.builder(Purpose.CONTENT_KEY_ENVELOPE, 1).id("blob", TestKeys.id()).build();
      assertThatThrownBy(() -> PublicKeyEnvelopes.open(key, otherBlob, envelope))
          .isInstanceOf(CryptoException.class);
    }
  }

  @Test
  void rejectsEveryFlippedByteAndTruncation() throws Exception {
    try (MailboxPrivateKey key = MailboxPrivateKey.generate(3);
        Secret payload = Secret.random(TestKeys.RANDOM, 32)) {
      byte[] envelope = PublicKeyEnvelopes.seal(key.publicKey(), context, payload);
      for (int i = 0; i < envelope.length; i++) {
        byte[] tampered = envelope.clone();
        tampered[i] ^= 0x01;
        assertThatThrownBy(() -> PublicKeyEnvelopes.open(key, context, tampered))
            .isInstanceOf(CryptoException.class);
      }
      for (int length = 0; length < envelope.length; length += 7) {
        byte[] truncated = java.util.Arrays.copyOf(envelope, length);
        assertThatThrownBy(() -> PublicKeyEnvelopes.open(key, context, truncated))
            .isInstanceOf(CryptoException.class);
      }
    }
  }

  @Test
  void envelopesAreRandomized() throws Exception {
    try (MailboxPrivateKey key = MailboxPrivateKey.generate(1);
        Secret payload = Secret.random(TestKeys.RANDOM, 32)) {
      byte[] first = PublicKeyEnvelopes.seal(key.publicKey(), context, payload);
      byte[] second = PublicKeyEnvelopes.seal(key.publicKey(), context, payload);
      assertThat(first).isNotEqualTo(second);
    }
  }

  @Test
  void privateKeyReconstructsSamePublicKey() throws Exception {
    try (MailboxPrivateKey key = MailboxPrivateKey.generate(5);
        MailboxPrivateKey copy = MailboxPrivateKey.fromBytes(5, key.privateBytes().copy())) {
      assertThat(copy.publicKey()).isEqualTo(key.publicKey());
      assertThat(copy.publicKey().fingerprint()).isEqualTo(key.publicKey().fingerprint());
    }
  }
}
