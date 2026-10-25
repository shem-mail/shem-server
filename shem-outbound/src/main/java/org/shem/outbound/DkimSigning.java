package org.shem.outbound;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.SequenceInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Locale;
import java.util.Optional;
import org.apache.james.jdkim.DKIMSigner;
import org.apache.james.jdkim.api.BodyHasher;
import org.apache.james.jdkim.exceptions.FailException;
import org.jspecify.annotations.Nullable;
import org.shem.common.DurableFiles;
import org.shem.delivery.MessageSource;
import org.shem.identity.Domain;
import org.shem.identity.IdentityService;
import org.shem.policy.HeaderBlock;

/**
 * DKIM signing (RFC 6376, rsa-sha256, relaxed/relaxed) with per-domain keys under a server-secret
 * directory: {@code <selector>._domainkey.<domain>.key}, PKCS#8 PEM, owner-only. These keys are not
 * protected by any mailbox password; a leaked key or backup lets an attacker sign mail for the
 * domain but never unlocks a mailbox (ADR 0012). The signature is computed over, and prepended to,
 * exactly the bytes that are queued and transmitted.
 */
public final class DkimSigning {
  static final String SIGNED_HEADERS =
      "from:to:cc:reply-to:subject:date:message-id:in-reply-to:references:mime-version"
          + ":content-type:content-transfer-encoding";

  private final Path keyDirectory;
  private final IdentityService identity;

  public DkimSigning(Path keyDirectory, IdentityService identity) {
    this.keyDirectory = keyDirectory;
    this.identity = identity;
  }

  /** A signed message source, or {@code message} unchanged when the domain has no key. */
  public MessageSource sign(String fromDomain, MessageSource message)
      throws IOException, SigningException {
    Optional<Domain> domain = identity.directory().domainByName(fromDomain);
    String selector = domain.map(Domain::dkimSelector).orElse(null);
    if (domain.isEmpty() || selector == null) {
      return message;
    }
    PrivateKey key = loadKey(keyFile(selector, domain.get().name()));
    if (key == null) {
      return message;
    }
    String header;
    String template =
        "v=1; a=rsa-sha256; c=relaxed/relaxed; d="
            + domain.get().name()
            + "; s="
            + selector
            + "; h="
            + SIGNED_HEADERS
            + "; bh=; b=;";
    // Streaming: headers are read with a bound and the body is hashed as it streams, instead of
    // jDKIM's sign(InputStream), which parses the whole message into memory.
    try (InputStream in = message.open()) {
      DKIMSigner signer = new DKIMSigner(template, key);
      HeaderBlock headers = HeaderBlock.read(in);
      if (!headers.complete()) {
        throw new SigningException(new IOException("header section too large"));
      }
      BodyHasher hasher = signer.newBodyHasher(signer.newSignatureRecordTemplate(template));
      try (OutputStream body = hasher.getOutputStream()) {
        in.transferTo(body);
      }
      header = signer.sign(headers, hasher);
    } catch (FailException | RuntimeException e) {
      throw new SigningException(e);
    }
    byte[] prefix = (header + "\r\n").getBytes(StandardCharsets.US_ASCII);
    return new MessageSource() {
      @Override
      public InputStream open() throws IOException {
        return new SequenceInputStream(new ByteArrayInputStream(prefix), message.open());
      }

      @Override
      public long size() {
        return prefix.length + message.size();
      }
    };
  }

  Path keyFile(String selector, String domain) {
    return keyDirectory.resolve(
        selector + "._domainkey." + domain.toLowerCase(Locale.ROOT) + ".key");
  }

  private static @Nullable PrivateKey loadKey(Path file) throws IOException, SigningException {
    if (!Files.exists(file)) {
      return null;
    }
    String pem = Files.readString(file, StandardCharsets.US_ASCII);
    String body =
        pem.replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replaceAll("\\s", "");
    try {
      return KeyFactory.getInstance("RSA")
          .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(body)));
    } catch (java.security.GeneralSecurityException | IllegalArgumentException e) {
      throw new SigningException(e);
    }
  }

  /**
   * Generates an RSA-2048 key for {@code selector} and {@code domain}, writes it owner-only, and
   * returns the DNS TXT record value to publish. Refuses to overwrite an existing key, so rotation
   * means a new selector and in-flight signatures stay verifiable.
   */
  public String generate(String selector, String domain) throws IOException, SigningException {
    DurableFiles.createPrivateDirectories(keyDirectory);
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
      generator.initialize(2048);
      KeyPair pair = generator.generateKeyPair();
      String pem =
          "-----BEGIN PRIVATE KEY-----\n"
              + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                  .encodeToString(pair.getPrivate().getEncoded())
              + "\n-----END PRIVATE KEY-----\n";
      DurableFiles.writeNew(keyFile(selector, domain), pem.getBytes(StandardCharsets.US_ASCII));
      return txtRecord(pair.getPrivate());
    } catch (java.security.GeneralSecurityException e) {
      throw new SigningException(e);
    }
  }

  /** The DNS TXT value publishing the public half of an RSA private key. */
  static String txtRecord(PrivateKey key) throws java.security.GeneralSecurityException {
    if (!(key instanceof RSAPrivateCrtKey crt)) {
      throw new java.security.InvalidKeyException("not an RSA CRT key");
    }
    byte[] publicKey =
        KeyFactory.getInstance("RSA")
            .generatePublic(new RSAPublicKeySpec(crt.getModulus(), crt.getPublicExponent()))
            .getEncoded();
    return "v=DKIM1; k=rsa; p=" + Base64.getEncoder().encodeToString(publicKey);
  }

  /** The signer could not produce a signature; the message is not queued unsigned. */
  public static final class SigningException extends Exception {
    private static final long serialVersionUID = 1L;

    SigningException(Throwable cause) {
      super("DKIM signing failed", cause);
    }
  }
}
