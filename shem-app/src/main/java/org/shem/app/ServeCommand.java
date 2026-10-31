package org.shem.app;

import java.io.PrintStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import javax.net.ssl.SSLContext;
import org.jspecify.annotations.Nullable;
import org.shem.http.AdminApi;
import org.shem.http.ChallengeRole;
import org.shem.http.DkimKeys;
import org.shem.http.HttpRole;
import org.shem.http.HttpSettings;
import org.shem.http.MtaStsPolicy;
import org.shem.imap.ImapRole;
import org.shem.outbound.DkimSigning;
import org.shem.outbound.OutboundDelivery;
import org.shem.outbound.OutboundQueue;
import org.shem.outbound.OutboundSettings;
import org.shem.policy.DnsResolver;
import org.shem.policy.DnsjavaResolver;
import org.shem.policy.Greylist;
import org.shem.policy.InboundPolicy;
import org.shem.policy.RulesFile;
import org.shem.smtp.InboundSettings;
import org.shem.smtp.InboundSmtpRole;
import org.shem.smtp.SubmissionRole;
import org.shem.smtp.SubmissionSettings;
import org.shem.tls.Acme4jAuthority;
import org.shem.tls.CertificateGenerations;
import org.shem.tls.CertificateRenewal;
import org.shem.tls.CertificateWatcher;
import org.shem.tls.Http01Challenges;
import org.shem.tls.ReloadableTlsContext;

/**
 * Runs the configured listeners until the process is asked to stop. Startup validates the
 * certificate before any listener opens; shutdown closes listeners first, then revokes all sessions
 * so every unlocked mailbox is locked again.
 */
final class ServeCommand {
  private static final System.Logger LOG = System.getLogger(ServeCommand.class.getName());

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
    if (tlsConfig == null
        || (config.imap() == null
            && config.smtp() == null
            && config.submission() == null
            && config.http() == null)) {
      out.println("nothing to serve: configure tls.* and imap.*, smtp.*, submission.*, or http.*");
      return 2;
    }
    ShemConfig.Acme acme = tlsConfig.acme();
    try (Services services = Services.start(config);
        Acme automatic = acme == null ? null : startAcme(services, tlsConfig, acme)) {
      if (automatic != null && !automatic.renewal.awaitCertificate(stop)) {
        out.println("stopped before a certificate was issued");
        return 0;
      }
      ReloadableTlsContext tls =
          ReloadableTlsContext.open(
              tlsConfig.certificateChain(),
              tlsConfig.privateKey(),
              tlsConfig.hostNames(),
              services.clock);
      Supplier<CertificateRenewal.Status> certificates;
      if (automatic != null) {
        automatic.renewal.attach(tls);
        automatic.renewal.start(Duration.ofMinutes(5));
        certificates = automatic.renewal::status;
      } else {
        certificates =
            () ->
                new CertificateRenewal.Status(
                    tls.notAfter(), null, services.clock.instant(), 0, tls.lastFailure(), null);
      }
      String hostName = tlsConfig.hostNames().get(0);
      ShemConfig.Policy policySettings = config.policy();
      DnsResolver dns =
          new DnsjavaResolver(
              policySettings.dnsServers(),
              policySettings.dnsTimeout(),
              10_000,
              Duration.ofHours(1));
      try (CertificateWatcher watcher =
              new CertificateWatcher(
                  tls,
                  tlsConfig.certificateChain(),
                  tlsConfig.privateKey(),
                  Duration.ofMinutes(1));
          Timers timers = new Timers();
          ImapRole imap = startImap(services, tls, hostName);
          InboundSmtpRole smtp = startSmtp(services, tls, hostName, timers.executor, dns);
          Outbound outbound = startOutbound(services, hostName, dns);
          SubmissionRole submission =
              startSubmission(services, tls, hostName, outbound == null ? null : outbound.relay);
          HttpRole http = startHttp(services, tls, hostName, certificates)) {
        if (http != null) {
          out.println("http api listening on port " + http.port());
        }
        if (imap != null) {
          out.println("imap listening on port " + imap.port());
        }
        if (smtp != null) {
          out.println("smtp listening on port " + smtp.port());
        }
        if (submission != null) {
          if (submission.implicitTlsPort() > 0) {
            out.println(
                "submission (implicit TLS) listening on port " + submission.implicitTlsPort());
          }
          if (submission.startTlsPort() > 0) {
            out.println("submission (STARTTLS) listening on port " + submission.startTlsPort());
          }
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
      Services services,
      ReloadableTlsContext tls,
      String hostName,
      ScheduledExecutorService timers,
      DnsResolver dns)
      throws Exception {
    ShemConfig.Smtp smtp = config.smtp();
    if (smtp == null) {
      return null;
    }
    ShemConfig.Policy settings = config.policy();
    InboundPolicy policy =
        new InboundPolicy(
            new InboundPolicy.Settings(
                hostName,
                settings.junkScore(),
                settings.dmarcReject(),
                settings.dangerousAttachments(),
                settings.blocklists()),
            dns,
            services.random);
    Path rulesPath = settings.rulesFile();
    if (rulesPath != null) {
      RulesFile rules = new RulesFile(rulesPath, policy);
      rules.load();
      // The task never throws; a failed reload is reported and the previous rules stay active.
      var unused =
          timers.scheduleWithFixedDelay(
              () -> {
                if (rules.reloadIfChanged() == RulesFile.Reload.REJECTED) {
                  LOG.log(
                      System.Logger.Level.WARNING,
                      "rules reload rejected, keeping previous rules: {0}",
                      rules.lastError());
                }
              },
              1,
              1,
              TimeUnit.MINUTES);
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
        policy,
        settings.greylist()
            ? new Greylist(Greylist.Settings.DEFAULT, services.clock, services.random)
            : null,
        tls,
        services.ids,
        services.random,
        services.clock);
  }

  /** ACME renewal and the port-80 listener it needs (ADR 0018). */
  private static final class Acme implements AutoCloseable {
    final CertificateRenewal renewal;
    final ChallengeRole port80;

    Acme(CertificateRenewal renewal, ChallengeRole port80) {
      this.renewal = renewal;
      this.port80 = port80;
    }

    @Override
    public void close() {
      renewal.close();
      port80.close();
    }
  }

  private Acme startAcme(Services services, ShemConfig.Tls tlsConfig, ShemConfig.Acme acme)
      throws Exception {
    CertificateGenerations generations =
        new CertificateGenerations(services.data.acme(), tlsConfig.hostNames());
    Http01Challenges challenges = new Http01Challenges();
    CertificateRenewal renewal =
        new CertificateRenewal(
            generations,
            new Acme4jAuthority(acme.directory(), generations.accountKeyFile(), acme.email()),
            challenges,
            tlsConfig.hostNames(),
            services.clock,
            services.random);
    ChallengeRole port80 =
        ChallengeRole.start(resolve(acme.challengeBind()), challenges, tlsConfig.hostNames());
    out.println("acme challenge listener on port " + port80.port());
    if (generations.current(services.clock.instant()).isEmpty()) {
      out.println("no valid certificate yet; requesting one before opening TLS listeners");
    }
    return new Acme(renewal, port80);
  }

  private @Nullable HttpRole startHttp(
      Services services,
      ReloadableTlsContext tls,
      String hostName,
      Supplier<CertificateRenewal.Status> certificates)
      throws Exception {
    ShemConfig.Http http = config.http();
    if (http == null) {
      return null;
    }
    String origin = http.origin();
    return HttpRole.start(
        new HttpSettings(
            resolve(http.bind()),
            origin == null ? "https://" + hostName : origin,
            64,
            64 * 1024,
            10_000,
            10,
            http.idleTimeout(),
            http.absoluteLifetime(),
            Duration.ofMinutes(5),
            mtaStsPolicy(hostName)),
        services.sessions,
        services.lifecycle,
        services.identity,
        new AdminApi.Services(
            services.admins,
            services.identity,
            services.provisioning,
            dkimKeys(services),
            config.bootstrapValidity(),
            hostName,
            certificates),
        tls,
        services.random,
        services.clock);
  }

  private @Nullable MtaStsPolicy mtaStsPolicy(String hostName) {
    ShemConfig.MtaSts mtaSts = config.mtaSts();
    if (mtaSts == null) {
      return null;
    }
    return new MtaStsPolicy(
        MtaStsPolicy.Mode.valueOf(mtaSts.mode().toUpperCase(java.util.Locale.ROOT)),
        List.of(hostName),
        mtaSts.maxAge());
  }

  private static DkimKeys dkimKeys(Services services) {
    DkimSigning signing = new DkimSigning(services.data.dkimKeys(), services.identity);
    return new DkimKeys() {
      @Override
      public String generate(String selector, String domain) throws Exception {
        return signing.generate(selector, domain);
      }

      @Override
      public Optional<String> publishedRecord(String selector, String domain) throws Exception {
        return signing.publishedRecord(selector, domain);
      }
    };
  }

  /** The outbound queue, its delivery worker, and the submission relay using them. */
  private static final class Outbound implements AutoCloseable {
    final SubmissionRole.Relay relay;
    final OutboundDelivery delivery;

    Outbound(SubmissionRole.Relay relay, OutboundDelivery delivery) {
      this.relay = relay;
      this.delivery = delivery;
    }

    @Override
    public void close() {
      delivery.close();
    }
  }

  private @Nullable Outbound startOutbound(Services services, String hostName, DnsResolver dns)
      throws Exception {
    ShemConfig.Outbound settings = config.outbound();
    if (settings == null) {
      return null;
    }
    OutboundQueue queue =
        OutboundQueue.open(
            services.data.queue(),
            new OutboundQueue.Limits(settings.maxItems(), settings.maxBytes(), settings.lifetime()),
            services.ids,
            services.clock);
    OutboundDelivery delivery =
        OutboundDelivery.create(
            queue,
            new OutboundSettings(
                hostName,
                25,
                Duration.ofSeconds(30),
                Duration.ofMinutes(5),
                Duration.ofMinutes(10),
                SSLContext.getDefault(),
                OutboundSettings.DEFAULT_RETRIES,
                settings.maxConcurrent(),
                100),
            dns,
            services.delivery,
            services.identity,
            services.random,
            services.clock);
    delivery.start(Duration.ofSeconds(30));
    return new Outbound(
        new SubmissionRole.Relay(
            queue, new DkimSigning(services.data.dkimKeys(), services.identity)),
        delivery);
  }

  private @Nullable SubmissionRole startSubmission(
      Services services,
      ReloadableTlsContext tls,
      String hostName,
      SubmissionRole.@Nullable Relay relay)
      throws Exception {
    ShemConfig.Submission submission = config.submission();
    if (submission == null) {
      return null;
    }
    InetSocketAddress implicit = submission.implicitTlsBind();
    InetSocketAddress starttls = submission.startTlsBind();
    return SubmissionRole.start(
        new SubmissionSettings(
            implicit == null ? null : resolve(implicit),
            starttls == null ? null : resolve(starttls),
            hostName,
            submission.maxConnections(),
            submission.maxConnectionsPerIp(),
            300,
            config.maxMessageBytes(),
            SMTP_MEMORY_THRESHOLD,
            submission.maxRecipients(),
            submission.recipientsPerHour(),
            services.data.spool().resolve("submission")),
        services.sessions,
        services.identity,
        services.delivery,
        relay,
        tls,
        services.ids,
        services.random,
        services.clock);
  }

  /** Background timers (rules reload), stopped with the listeners. */
  private static final class Timers implements AutoCloseable {
    final ScheduledExecutorService executor =
        Executors.newSingleThreadScheduledExecutor(
            Thread.ofPlatform().name("shem-timer").daemon(true).factory());

    @Override
    public void close() {
      executor.shutdownNow();
    }
  }

  private static InetSocketAddress resolve(InetSocketAddress unresolved) throws Exception {
    return new InetSocketAddress(
        InetAddress.getByName(unresolved.getHostString()), unresolved.getPort());
  }
}
