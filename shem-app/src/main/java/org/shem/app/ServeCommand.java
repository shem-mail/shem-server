package org.shem.app;

import java.io.PrintStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.time.Clock;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import org.shem.imap.ImapRole;
import org.shem.tls.CertificateWatcher;
import org.shem.tls.ReloadableTlsContext;

/**
 * Runs the configured listeners until the process is asked to stop. Startup validates the
 * certificate before any listener opens; shutdown closes listeners first, then revokes all sessions
 * so every unlocked mailbox is locked again.
 */
final class ServeCommand {
  private final ShemConfig config;
  private final PrintStream out;

  ServeCommand(ShemConfig config, PrintStream out) {
    this.config = config;
    this.out = out;
  }

  int run(CountDownLatch stop) throws Exception {
    ShemConfig.Tls tlsConfig = config.tls();
    if (tlsConfig == null || config.imap() == null) {
      out.println("nothing to serve: configure tls.* and imap.bind");
      return 2;
    }
    try (Services services = Services.start(config)) {
      ReloadableTlsContext tls =
          ReloadableTlsContext.open(
              tlsConfig.certificateChain(),
              tlsConfig.privateKey(),
              tlsConfig.hostNames(),
              Clock.systemUTC());
      ShemConfig.Imap imapConfig = config.imap();
      InetSocketAddress bind =
          new InetSocketAddress(
              InetAddress.getByName(imapConfig.bind().getHostString()),
              imapConfig.bind().getPort());
      CertificateWatcher watcher =
          new CertificateWatcher(
              tls, tlsConfig.certificateChain(), tlsConfig.privateKey(), Duration.ofMinutes(1));
      try (ImapRole imap =
          ImapRole.start(
              new ImapRole.Settings(
                  bind,
                  tlsConfig.hostNames().get(0),
                  imapConfig.maxConnections(),
                  imapConfig.maxConnectionsPerIp(),
                  (int) config.maxMessageBytes(),
                  1800),
              services.sessions,
              tls)) {
        out.println("imap listening on port " + imap.port());
        stop.await();
        out.println("shutting down");
      } finally {
        watcher.close();
      }
    }
    return 0;
  }
}
