package org.shem.imap;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.Test;

class ShemAuthenticateProcessorTest {
  private static String b64(String s) {
    return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
  }

  @Test
  void decodesPlainWithEmptyOrMatchingAuthzid() {
    assertThat(ShemAuthenticateProcessor.decode(b64("\0alice@example.org\0pw")))
        .containsExactly("alice@example.org", "pw");
    assertThat(ShemAuthenticateProcessor.decode(b64("alice@example.org\0alice@example.org\0pw")))
        .containsExactly("alice@example.org", "pw");
  }

  @Test
  void rejectsDelegationMalformedAndEmptyFields() {
    assertThat(ShemAuthenticateProcessor.decode(b64("admin@example.org\0alice@example.org\0pw")))
        .isNull();
    assertThat(ShemAuthenticateProcessor.decode(b64("\0alice@example.org"))).isNull();
    assertThat(ShemAuthenticateProcessor.decode(b64("\0\0pw"))).isNull();
    assertThat(ShemAuthenticateProcessor.decode(b64("\0a\0b\0c"))).isNull();
    assertThat(ShemAuthenticateProcessor.decode("***not base64***")).isNull();
  }
}
