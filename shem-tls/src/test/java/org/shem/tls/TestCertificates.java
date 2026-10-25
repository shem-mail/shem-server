package org.shem.tls;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/** Self-signed test certificates written as PEM (test scope only). */
public final class TestCertificates {
  private TestCertificates() {}

  public record Files2(Path chain, Path key, X509Certificate certificate) {}

  public static Files2 write(Path directory, String host, Instant notBefore, Duration validity)
      throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair pair = generator.generateKeyPair();
    return write(directory, host, notBefore, validity, pair, pair);
  }

  /** Writes a certificate for {@code certKey} but stores {@code fileKey} as the private key. */
  public static Files2 write(
      Path directory,
      String host,
      Instant notBefore,
      Duration validity,
      KeyPair certKey,
      KeyPair fileKey)
      throws Exception {
    X500Name name = new X500Name("CN=" + host);
    JcaX509v3CertificateBuilder builder =
        new JcaX509v3CertificateBuilder(
            name,
            BigInteger.valueOf(System.nanoTime()),
            Date.from(notBefore),
            Date.from(notBefore.plus(validity)),
            name,
            certKey.getPublic());
    builder.addExtension(
        Extension.subjectAlternativeName,
        false,
        new GeneralNames(new GeneralName(GeneralName.dNSName, host)));
    X509Certificate certificate =
        new JcaX509CertificateConverter()
            .getCertificate(
                builder.build(
                    new JcaContentSignerBuilder("SHA256withECDSA").build(certKey.getPrivate())));
    Files.createDirectories(directory);
    Path chain = directory.resolve("fullchain.pem");
    Path key = directory.resolve("privkey.pem");
    writePem(chain, "CERTIFICATE", certificate.getEncoded());
    writePem(key, "PRIVATE KEY", fileKey.getPrivate().getEncoded());
    return new Files2(chain, key, certificate);
  }

  private static void writePem(Path file, String type, byte[] der) throws IOException {
    String body =
        Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der);
    Path temp = file.resolveSibling(file.getFileName() + ".tmp");
    Files.writeString(
        temp,
        "-----BEGIN " + type + "-----\n" + body + "\n-----END " + type + "-----\n",
        StandardCharsets.US_ASCII);
    Files.move(
        temp,
        file,
        java.nio.file.StandardCopyOption.REPLACE_EXISTING,
        java.nio.file.StandardCopyOption.ATOMIC_MOVE);
  }

  /** Trust manager accepting exactly the given certificate (test clients only). */
  public static javax.net.ssl.SSLContext clientTrusting(X509Certificate... trusted)
      throws Exception {
    java.security.KeyStore store = java.security.KeyStore.getInstance("PKCS12");
    store.load(null, null);
    for (int i = 0; i < trusted.length; i++) {
      store.setCertificateEntry("c" + i, trusted[i]);
    }
    javax.net.ssl.TrustManagerFactory factory =
        javax.net.ssl.TrustManagerFactory.getInstance(
            javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm());
    factory.init(store);
    javax.net.ssl.SSLContext context = javax.net.ssl.SSLContext.getInstance("TLS");
    context.init(null, factory.getTrustManagers(), null);
    return context;
  }
}
