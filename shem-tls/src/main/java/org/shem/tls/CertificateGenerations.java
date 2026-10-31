package org.shem.tls;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.KeyPair;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.shem.common.DurableFiles;

/**
 * ACME-managed certificate files (ADR 0018). Each issued certificate is written, complete, into a
 * new {@code gen-N/} directory ({@code chain.pem} and an owner-only {@code key.pem}), validated,
 * and then published by atomically renaming the symbolic link {@code live -> gen-N}. A crash at any
 * point leaves {@code live} on either the old or the new generation, never on a mismatched
 * chain/key pair. The current and previous generations are kept; older ones are removed.
 */
public final class CertificateGenerations {
  static final String LIVE = "live";
  private static final String PREFIX = "gen-";

  private final Path directory;
  private final List<String> hosts;

  public CertificateGenerations(Path directory, List<String> hosts) {
    this.directory = directory.toAbsolutePath();
    this.hosts = List.copyOf(hosts);
  }

  /** The chain file listeners read; resolves through {@code live}. */
  public Path chainFile() {
    return directory.resolve(LIVE).resolve("chain.pem");
  }

  public Path keyFile() {
    return directory.resolve(LIVE).resolve("key.pem");
  }

  public Path accountKeyFile() {
    return directory.resolve("account.pem");
  }

  /** The live bundle if it exists and is valid at {@code now}. */
  public Optional<CertificateBundle> current(Instant now) {
    if (!Files.exists(chainFile()) || !Files.exists(keyFile())) {
      return Optional.empty();
    }
    try {
      return Optional.of(CertificateBundle.load(chainFile(), keyFile(), hosts, now));
    } catch (CertificateBundle.InvalidCertificateException e) {
      return Optional.empty();
    }
  }

  /**
   * Writes and validates a new generation, then makes it live. On validation failure the new
   * generation is removed and {@code live} is untouched.
   */
  public CertificateBundle install(List<X509Certificate> chain, KeyPair key, Instant now)
      throws IOException, CertificateBundle.InvalidCertificateException {
    if (chain.isEmpty()) {
      throw new CertificateBundle.InvalidCertificateException("empty certificate chain");
    }
    DurableFiles.createPrivateDirectories(directory);
    int generation = latestGeneration() + 1;
    Path target = directory.resolve(PREFIX + generation);
    DurableFiles.createPrivateDirectories(target);
    CertificateBundle bundle;
    try {
      DurableFiles.writeNew(
          target.resolve("key.pem"), Pem.privateKey(key).getBytes(StandardCharsets.US_ASCII));
      DurableFiles.writeNew(
          target.resolve("chain.pem"), Pem.chain(chain).getBytes(StandardCharsets.US_ASCII));
      bundle =
          CertificateBundle.load(
              target.resolve("chain.pem"), target.resolve("key.pem"), hosts, now);
    } catch (CertificateEncodingException e) {
      deleteGeneration(target);
      throw new CertificateBundle.InvalidCertificateException("certificate not encodable", e);
    } catch (IOException | CertificateBundle.InvalidCertificateException | RuntimeException e) {
      deleteGeneration(target);
      throw e;
    }
    Path link = directory.resolve(".live-" + generation);
    Files.deleteIfExists(link);
    Files.createSymbolicLink(link, Path.of(PREFIX + generation));
    Files.move(link, directory.resolve(LIVE), StandardCopyOption.ATOMIC_MOVE);
    DurableFiles.syncDirectory(directory);
    prune(generation);
    return bundle;
  }

  int latestGeneration() throws IOException {
    int latest = 0;
    for (int generation : generations()) {
      latest = Math.max(latest, generation);
    }
    return latest;
  }

  private List<Integer> generations() throws IOException {
    List<Integer> out = new ArrayList<>();
    if (!Files.isDirectory(directory)) {
      return out;
    }
    try (DirectoryStream<Path> entries = Files.newDirectoryStream(directory, PREFIX + "*")) {
      for (Path entry : entries) {
        try {
          out.add(Integer.parseInt(entry.getFileName().toString().substring(PREFIX.length())));
        } catch (NumberFormatException e) {
          // not ours; leave it alone
        }
      }
    }
    return out;
  }

  /** Keeps {@code live} and the generation before it; older ones, complete or not, are removed. */
  private void prune(int live) throws IOException {
    for (int generation : generations()) {
      if (generation < live - 1) {
        deleteGeneration(directory.resolve(PREFIX + generation));
      }
    }
  }

  private static void deleteGeneration(Path generation) throws IOException {
    if (!Files.isDirectory(generation, LinkOption.NOFOLLOW_LINKS)) {
      return;
    }
    try (DirectoryStream<Path> files = Files.newDirectoryStream(generation)) {
      for (Path file : files) {
        Files.deleteIfExists(file);
      }
    }
    Files.deleteIfExists(generation);
  }
}
