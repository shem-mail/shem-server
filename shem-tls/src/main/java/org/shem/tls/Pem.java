package org.shem.tls;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;

/** PEM encoding of keys and chains in the formats {@link CertificateBundle} reads. */
final class Pem {
  private static final Base64.Encoder MIME =
      Base64.getMimeEncoder(64, "\n".getBytes(java.nio.charset.StandardCharsets.US_ASCII));

  private Pem() {}

  static KeyPair newEcKeyPair() {
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
      generator.initialize(new ECGenParameterSpec("secp256r1"));
      return generator.generateKeyPair();
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("EC P-256 is unavailable", e);
    }
  }

  static String privateKey(KeyPair pair) {
    return block("PRIVATE KEY", pair.getPrivate().getEncoded());
  }

  static String chain(List<X509Certificate> chain) throws CertificateEncodingException {
    StringBuilder out = new StringBuilder();
    for (X509Certificate certificate : chain) {
      out.append(block("CERTIFICATE", certificate.getEncoded()));
    }
    return out.toString();
  }

  /** An account key file: the PKCS#8 private key followed by its X.509 public key. */
  static String keyPair(KeyPair pair) {
    return block("PRIVATE KEY", pair.getPrivate().getEncoded())
        + block("PUBLIC KEY", pair.getPublic().getEncoded());
  }

  static KeyPair readKeyPair(String pem) throws IOException {
    byte[] privateDer = decode(pem, "PRIVATE KEY");
    byte[] publicDer = decode(pem, "PUBLIC KEY");
    try {
      KeyFactory factory = KeyFactory.getInstance("EC");
      PrivateKey privateKey = factory.generatePrivate(new PKCS8EncodedKeySpec(privateDer));
      PublicKey publicKey = factory.generatePublic(new X509EncodedKeySpec(publicDer));
      return new KeyPair(publicKey, privateKey);
    } catch (GeneralSecurityException e) {
      throw new IOException("account key unusable", e);
    } finally {
      java.util.Arrays.fill(privateDer, (byte) 0);
    }
  }

  private static byte[] decode(String pem, String type) throws IOException {
    String begin = "-----BEGIN " + type + "-----";
    int start = pem.indexOf(begin);
    int end = pem.indexOf("-----END " + type + "-----");
    if (start < 0 || end < start) {
      throw new IOException("account key file lacks a " + type + " block");
    }
    try {
      return Base64.getMimeDecoder().decode(pem.substring(start + begin.length(), end));
    } catch (IllegalArgumentException e) {
      throw new IOException("account key file malformed", e);
    }
  }

  private static String block(String type, byte[] der) {
    return "-----BEGIN "
        + type
        + "-----\n"
        + MIME.encodeToString(der)
        + "\n-----END "
        + type
        + "-----\n";
  }
}
