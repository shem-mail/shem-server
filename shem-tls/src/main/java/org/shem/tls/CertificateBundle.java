package org.shem.tls;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Locale;

/**
 * A validated certificate chain and its private key, loaded from PEM files. The key must be PKCS#8
 * ({@code BEGIN PRIVATE KEY}); convert legacy {@code BEGIN RSA/EC PRIVATE KEY} files with {@code
 * openssl pkcs8 -topk8 -nocrypt}.
 */
public final class CertificateBundle {
  private final List<X509Certificate> chain;
  private final PrivateKey privateKey;

  private CertificateBundle(List<X509Certificate> chain, PrivateKey privateKey) {
    this.chain = List.copyOf(chain);
    this.privateKey = privateKey;
  }

  /** Thrown when files are missing, malformed, mismatched, expired, or do not cover a host. */
  public static final class InvalidCertificateException extends Exception {
    private static final long serialVersionUID = 1L;

    public InvalidCertificateException(String message) {
      super(message);
    }

    public InvalidCertificateException(String message, Throwable cause) {
      super(message, cause);
    }
  }

  /**
   * Loads and validates a bundle: non-empty chain, leaf currently valid, private key matching the
   * leaf, and every required host name covered by the leaf's DNS subject alternative names.
   */
  public static CertificateBundle load(
      Path chainFile, Path keyFile, List<String> requiredHosts, Instant now)
      throws InvalidCertificateException {
    List<X509Certificate> chain = readChain(chainFile);
    PrivateKey key = readPrivateKey(keyFile);
    X509Certificate leaf = chain.get(0);
    try {
      leaf.checkValidity(java.util.Date.from(now));
    } catch (CertificateException e) {
      throw new InvalidCertificateException("certificate is not currently valid", e);
    }
    if (!matches(key, leaf.getPublicKey())) {
      throw new InvalidCertificateException("private key does not match certificate");
    }
    List<String> names = dnsNames(leaf);
    for (String host : requiredHosts) {
      if (!covers(names, host)) {
        throw new InvalidCertificateException("certificate does not cover a configured host name");
      }
    }
    for (int i = 0; i + 1 < chain.size(); i++) {
      try {
        chain.get(i).verify(chain.get(i + 1).getPublicKey());
      } catch (GeneralSecurityException e) {
        throw new InvalidCertificateException("certificate chain is not linked", e);
      }
    }
    return new CertificateBundle(chain, key);
  }

  public List<X509Certificate> chain() {
    return chain;
  }

  PrivateKey privateKey() {
    return privateKey;
  }

  public Instant notAfter() {
    return chain.get(0).getNotAfter().toInstant();
  }

  private static List<X509Certificate> readChain(Path file) throws InvalidCertificateException {
    try {
      CertificateFactory factory = CertificateFactory.getInstance("X.509");
      Collection<? extends java.security.cert.Certificate> parsed =
          factory.generateCertificates(new ByteArrayInputStream(Files.readAllBytes(file)));
      List<X509Certificate> chain = new ArrayList<>();
      for (java.security.cert.Certificate c : parsed) {
        chain.add((X509Certificate) c);
      }
      if (chain.isEmpty()) {
        throw new InvalidCertificateException("no certificates in chain file");
      }
      return chain;
    } catch (IOException e) {
      throw new InvalidCertificateException("certificate file unreadable", e);
    } catch (CertificateException e) {
      throw new InvalidCertificateException("certificate file malformed", e);
    }
  }

  private static PrivateKey readPrivateKey(Path file) throws InvalidCertificateException {
    byte[] der;
    try {
      String pem = Files.readString(file, StandardCharsets.US_ASCII);
      int begin = pem.indexOf("-----BEGIN PRIVATE KEY-----");
      int end = pem.indexOf("-----END PRIVATE KEY-----");
      if (begin < 0 || end < begin) {
        throw new InvalidCertificateException("key file must contain a PKCS#8 PRIVATE KEY block");
      }
      String body = pem.substring(begin + "-----BEGIN PRIVATE KEY-----".length(), end);
      der = Base64.getMimeDecoder().decode(body);
    } catch (IOException e) {
      throw new InvalidCertificateException("key file unreadable", e);
    } catch (IllegalArgumentException e) {
      throw new InvalidCertificateException("key file malformed", e);
    }
    try {
      for (String algorithm : new String[] {"EC", "RSA", "Ed25519"}) {
        try {
          return KeyFactory.getInstance(algorithm).generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (InvalidKeySpecException e) {
          // try the next algorithm
        }
      }
      throw new InvalidCertificateException("unsupported private key algorithm");
    } catch (GeneralSecurityException e) {
      throw new InvalidCertificateException("private key unusable", e);
    } finally {
      Arrays.fill(der, (byte) 0);
    }
  }

  private static boolean matches(PrivateKey key, PublicKey publicKey) {
    String algorithm =
        switch (key.getAlgorithm()) {
          case "EC" -> "SHA256withECDSA";
          case "RSA" -> "SHA256withRSA";
          default -> key.getAlgorithm();
        };
    try {
      byte[] challenge = "shem-key-match".getBytes(StandardCharsets.US_ASCII);
      Signature signer = Signature.getInstance(algorithm);
      signer.initSign(key);
      signer.update(challenge);
      byte[] signature = signer.sign();
      Signature verifier = Signature.getInstance(algorithm);
      verifier.initVerify(publicKey);
      verifier.update(challenge);
      return verifier.verify(signature);
    } catch (GeneralSecurityException e) {
      return false;
    }
  }

  private static List<String> dnsNames(X509Certificate certificate)
      throws InvalidCertificateException {
    List<String> names = new ArrayList<>();
    try {
      Collection<List<?>> alternatives = certificate.getSubjectAlternativeNames();
      if (alternatives != null) {
        for (List<?> entry : alternatives) {
          if (entry.size() == 2
              && Integer.valueOf(2).equals(entry.get(0))
              && entry.get(1) instanceof String s) {
            names.add(s.toLowerCase(Locale.ROOT));
          }
        }
      }
    } catch (CertificateException e) {
      throw new InvalidCertificateException("subject alternative names unreadable", e);
    }
    return names;
  }

  static boolean covers(List<String> names, String host) {
    String h = host.toLowerCase(Locale.ROOT);
    for (String name : names) {
      if (name.equals(h)) {
        return true;
      }
      if (name.startsWith("*.")) {
        int dot = h.indexOf('.');
        if (dot > 0 && h.substring(dot + 1).equals(name.substring(2))) {
          return true;
        }
      }
    }
    return false;
  }
}
