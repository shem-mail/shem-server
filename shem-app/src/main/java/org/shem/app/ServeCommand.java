package org.shem.app;

import java.io.PrintStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import org.jspecify.annotations.Nullable;
import org.shem.imap.ImapRole;
import org.shem.smtp.InboundSettings;
import org.shem.smtp.InboundSmtpRole;
import org.shem.tls.CertificateWatcher;
import org.shem.tls.ReloadableTlsContext;

/**
 * Runs the configured listeners until the process is asked to stop. Startup validates the
 * certificate before any listener opens; shutdown closes listeners first, then revokes all sessions
 * so every unlocked mailbox is locked again.
 */
final class ServeCommand {
  /** Inbound messages larger than this are spooled to encrypted provisional files. */
  private static final int SMTP_MEMORY_THRESHOLD = 1 << 20;

  private final ShemConfig config;
  private final PrintStream out;

  ServeCommand(ShemConfig config, PrintStream out) {
    this.config = config;
    this.out = out;
  }

  @SuppressWarnings("try") // the watcher only needs to live as long as the listeners
  int run(CountDownLatch stop) throws Exception {
    ShemConfig.Tls tlsConfig = config.tls();
    if (tlsConfig == null || (config.imap() == null && config.smtp() == null)) {
      out.println("nothing to serve: configure tls.* and imap.bind and/or smtp.bind");
      return 2;
    }
    try (Services services = Services.start(config)) {
      ReloadableTlsContext tls =
          ReloadableTlsContext.open(
              tlsConfig.certificateChain(),
              tlsConfig.privateKey(),
              tlsConfig.hostNames(),
              services.clock);
      String hostName = tlsConfig.hostNames().get(0);
      try (CertificateWatcher watcher =
              new CertificateWatcher(
                  tls,
                  tlsConfig.certificateChain(),
                  tlsConfig.privateKey(),
                  Duration.ofMinutes(1));
          ImapRole imap = startImap(services, tls, hostName);
          InboundSmtpRole smtp = startSmtp(services, tls, hostName)) {
        if (imap != null) {
          out.println("imap listening on port " + imap.port());
        }
        if (smtp != null) {
          out.println("smtp listening on port " + smtp.port());
        }
        stop.await();
        out.println("shutting down");
      }
    }
    return 0;
  }

  private @Nullable ImapRole startImap(Services services, ReloadableTlsContext tls, String hostName)
      throws Exception {
    ShemConfig.Imap imap = config.imap();
    if (imap == null) {
      return null;
    }
    return ImapRole.start(
        new ImapRole.Settings(
            resolve(imap.bind()),
            hostName,
            imap.maxConnections(),
            imap.maxConnectionsPerIp(),
            (int) config.maxMessageBytes(),
            1800),
        services.sessions,
        tls);
  }

  private @Nullable InboundSmtpRole startSmtp(
      Services services, ReloadableTlsContext tls, String hostName) throws Exception {
    ShemConfig.Smtp smtp = config.smtp();
    if (smtp == null) {
      return null;
    }
    return InboundSmtpRole.start(
        new InboundSettings(
            resolve(smtp.bind()),
            hostName,
            smtp.maxConnections(),
            smtp.maxConnectionsPerIp(),
            300,
            config.maxMessageBytes(),
            SMTP_MEMORY_THRESHOLD,
            smtp.maxRecipients(),
            smtp.maxUnknownRecipients(),
            services.data.spool().resolve("inbound")),
        services.identity,
        services.delivery,
        tls,
        services.ids,
        services.random,
        services.clock);
  }

  private static InetSocketAddress resolve(InetSocketAddress unresolved) throws Exception {
    return new InetSocketAddress(
        InetAddress.getByName(unresolved.getHostString()), unresolved.getPort());
  }
}
