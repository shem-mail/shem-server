package org.shem.tls;

import java.lang.System.Logger.Level;
import java.net.Socket;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.X509ExtendedKeyManager;
import org.jspecify.annotations.Nullable;

/**
 * One {@link SSLContext} per listener set whose key material can be replaced atomically. New
 * handshakes use the current bundle; established sessions are unaffected. A failed reload keeps the
 * previous, still valid bundle and reports the failure; it never disables TLS.
 */
public final class ReloadableTlsContext {
  private static final System.Logger LOG = System.getLogger(ReloadableTlsContext.class.getName());
  private static final String[] PROTOCOLS = {"TLSv1.3", "TLSv1.2"};

  private final Path chainFile;
  private final Path keyFile;
  private final List<String> hosts;
  private final Clock clock;
  private final AtomicReference<X509ExtendedKeyManager> current = new AtomicReference<>();
  private final AtomicReference<Instant> notAfter = new AtomicReference<>(Instant.EPOCH);
  private final SSLContext context;
  private volatile @Nullable String lastFailure;

  private ReloadableTlsContext(Path chainFile, Path keyFile, List<String> hosts, Clock clock)
      throws GeneralSecurityException {
    this.chainFile = chainFile;
    this.keyFile = keyFile;
    this.hosts = List.copyOf(hosts);
    this.clock = clock;
    this.context = SSLContext.getInstance("TLS");
    this.context.init(new javax.net.ssl.KeyManager[] {new Delegating()}, null, null);
  }

  /** Loads the initial bundle; startup fails if it is invalid. */
  public static ReloadableTlsContext open(
      Path chainFile, Path keyFile, List<String> hosts, Clock clock)
      throws CertificateBundle.InvalidCertificateException, GeneralSecurityException {
    ReloadableTlsContext tls = new ReloadableTlsContext(chainFile, keyFile, hosts, clock);
    tls.install(CertificateBundle.load(chainFile, keyFile, hosts, clock.instant()));
    return tls;
  }

  public SSLContext sslContext() {
    return context;
  }

  /**
   * Server-mode engine with Shem's protocol policy (cipher suites: JDK defaults for TLS 1.2/1.3).
   */
  public SSLEngine newServerEngine() {
    SSLEngine engine = context.createSSLEngine();
    engine.setUseClientMode(false);
    engine.setSSLParameters(serverParameters());
    return engine;
  }

  public SSLParameters serverParameters() {
    SSLParameters parameters = context.getDefaultSSLParameters();
    parameters.setProtocols(PROTOCOLS);
    parameters.setUseCipherSuitesOrder(true);
    return parameters;
  }

  /**
   * Re-reads the files. Returns {@code true} if a new valid bundle was installed; on failure keeps
   * the current one and records a sanitized reason.
   */
  public boolean reload() {
    try {
      CertificateBundle bundle = CertificateBundle.load(chainFile, keyFile, hosts, clock.instant());
      install(bundle);
      lastFailure = null;
      return true;
    } catch (CertificateBundle.InvalidCertificateException | GeneralSecurityException e) {
      lastFailure = e.getMessage();
      LOG.log(
          Level.WARNING,
          "certificate reload rejected; keeping current certificate: " + e.getMessage());
      return false;
    }
  }

  public Instant notAfter() {
    return notAfter.get();
  }

  public @Nullable String lastFailure() {
    return lastFailure;
  }

  private void install(CertificateBundle bundle) throws GeneralSecurityException {
    KeyStore store = KeyStore.getInstance("PKCS12");
    try {
      store.load(null, null);
    } catch (java.io.IOException e) {
      throw new GeneralSecurityException("in-memory key store init failed", e);
    }
    char[] password = new char[0];
    store.setKeyEntry(
        "listener", bundle.privateKey(), password, bundle.chain().toArray(new X509Certificate[0]));
    KeyManagerFactory factory =
        KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    factory.init(store, password);
    for (javax.net.ssl.KeyManager manager : factory.getKeyManagers()) {
      if (manager instanceof X509ExtendedKeyManager x509) {
        current.set(x509);
        notAfter.set(bundle.notAfter());
        return;
      }
    }
    throw new GeneralSecurityException("no X509 key manager available");
  }

  /** Delegates every call to the currently installed key manager. */
  private final class Delegating extends X509ExtendedKeyManager {
    private X509ExtendedKeyManager delegate() {
      X509ExtendedKeyManager manager = current.get();
      if (manager == null) {
        throw new IllegalStateException("no certificate installed");
      }
      return manager;
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
      return delegate().getClientAliases(keyType, issuers);
    }

    @Override
    public @Nullable String chooseClientAlias(
        String[] keyType, Principal[] issuers, Socket socket) {
      return null;
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
      return delegate().getServerAliases(keyType, issuers);
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
      return delegate().chooseServerAlias(keyType, issuers, socket);
    }

    @Override
    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
      return delegate().chooseEngineServerAlias(keyType, issuers, engine);
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
      return delegate().getCertificateChain(alias);
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
      return delegate().getPrivateKey(alias);
    }
  }
}
