package org.shem.policy;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import org.apache.james.jdkim.DKIMSigner;

/** Synthetic messages and DKIM keys. */
final class Fixtures {
  private Fixtures() {}

  static String message(String from, String body) {
    return "From: Sender <"
        + from
        + ">\r\nTo: alice@example.org\r\nSubject: test\r\nDate: Sun, 25 Oct 2026 10:00:00 +0000\r\n"
        + "Message-ID: <fixture@example.net>\r\nMIME-Version: 1.0\r\n"
        + "Content-Type: text/plain; charset=utf-8\r\n\r\n"
        + body
        + "\r\n";
  }

  static KeyPair rsa() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    return generator.generateKeyPair();
  }

  /** The DNS TXT value publishing {@code keys}' public key. */
  static String keyRecord(KeyPair keys) {
    return "v=DKIM1; k=rsa; p=" + Base64.getEncoder().encodeToString(keys.getPublic().getEncoded());
  }

  /** Signs {@code message} for {@code domain} with selector {@code s1}; returns the signed text. */
  static String sign(String message, String domain, KeyPair keys) throws Exception {
    DKIMSigner signer =
        new DKIMSigner(
            "v=1; a=rsa-sha256; c=relaxed/relaxed; d="
                + domain
                + "; s=s1; h=from:to:subject:date:message-id; bh=; b=;",
            keys.getPrivate());
    String header = signer.sign(new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)));
    return header + "\r\n" + message;
  }

  static MessageInput input(String message) {
    byte[] bytes = message.getBytes(StandardCharsets.UTF_8);
    return () -> new ByteArrayInputStream(bytes);
  }
}
