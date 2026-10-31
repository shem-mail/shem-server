package org.shem.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;

class SymmetricKeyTest {
  private final AssociatedData context =
      AssociatedData.builder(Purpose.METADATA_JOURNAL, 1).number("record", 7).build();

  @Test
  void sealsAndOpensRecords() throws Exception {
    try (SymmetricKey key = SymmetricKey.generate(TestKeys.RANDOM)) {
      byte[] sealed = key.seal("folder: Inbox".getBytes(StandardCharsets.UTF_8), context);
      try (Secret opened = key.open(sealed, context)) {
        assertThat(new String(opened.exposeCopy(), StandardCharsets.UTF_8))
            .isEqualTo("folder: Inbox");
      }
    }
  }

  @Test
  void rejectsWrongContextAndWrongKey() throws Exception {
    try (SymmetricKey key = SymmetricKey.generate(TestKeys.RANDOM);
        SymmetricKey other = SymmetricKey.generate(TestKeys.RANDOM)) {
      byte[] sealed = key.seal(new byte[] {1, 2, 3}, context);
      AssociatedData moved =
          AssociatedData.builder(Purpose.METADATA_JOURNAL, 1).number("record", 8).build();
      assertThatThrownBy(() -> key.open(sealed, moved)).isInstanceOf(CryptoException.class);
      assertThatThrownBy(() -> other.open(sealed, context)).isInstanceOf(CryptoException.class);
    }
  }

  @Test
  void noncesDoNotRepeat() throws Exception {
    try (SymmetricKey key = SymmetricKey.generate(TestKeys.RANDOM)) {
      Set<ByteBuffer> nonces = new HashSet<>();
      for (int i = 0; i < 20_000; i++) {
        byte[] sealed = key.seal(new byte[0], context);
        assertThat(nonces.add(ByteBuffer.wrap(java.util.Arrays.copyOf(sealed, 12)))).isTrue();
      }
    }
  }

  @Test
  void derivationSeparatesPurposeAndContext() throws Exception {
    try (SymmetricKey root = SymmetricKey.generate(TestKeys.RANDOM);
        SymmetricKey a = root.derive(Purpose.METADATA_JOURNAL, new byte[] {1});
        SymmetricKey b = root.derive(Purpose.METADATA_JOURNAL, new byte[] {2});
        SymmetricKey c = root.derive(Purpose.SEARCH_INDEX, new byte[] {1});
        SymmetricKey a2 = root.derive(Purpose.METADATA_JOURNAL, new byte[] {1})) {
      assertThat(a.secret().contentEquals(a2.secret())).isTrue();
      assertThat(a.secret().contentEquals(b.secret())).isFalse();
      assertThat(a.secret().contentEquals(c.secret())).isFalse();
    }
  }

  @Test
  void closedSecretsAreUnusableAndZeroed() {
    Secret secret = Secret.random(TestKeys.RANDOM, 32);
    byte[] internal = secret.bytes();
    secret.close();
    assertThat(internal).containsOnly(0);
    assertThatThrownBy(secret::length).isInstanceOf(IllegalStateException.class);
    assertThat(secret.toString()).doesNotContain("0");
  }

  @Test
  void fingerprintsAreKeyedPurposeBoundAndDeterministic() throws Exception {
    byte[] data = "198.51.100.0/24|a@example.net".getBytes(StandardCharsets.UTF_8);
    try (SymmetricKey key = SymmetricKey.generate(TestKeys.RANDOM);
        SymmetricKey other = SymmetricKey.generate(TestKeys.RANDOM)) {
      byte[] first = key.fingerprint(Purpose.POLICY_FINGERPRINT, data);
      assertThat(first).hasSize(16).isEqualTo(key.fingerprint(Purpose.POLICY_FINGERPRINT, data));
      assertThat(other.fingerprint(Purpose.POLICY_FINGERPRINT, data)).isNotEqualTo(first);
      assertThat(key.fingerprint(Purpose.EXPORT, data)).isNotEqualTo(first);
      assertThat(key.fingerprint(Purpose.POLICY_FINGERPRINT, new byte[1])).isNotEqualTo(first);
    }
  }
}
