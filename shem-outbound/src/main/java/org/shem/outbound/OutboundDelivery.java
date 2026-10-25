package org.shem.outbound;

import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.LongAdder;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import org.shem.common.OpaqueId;
import org.shem.delivery.DeliveryRequest;
import org.shem.delivery.DeliveryService;
import org.shem.delivery.MessageSource;
import org.shem.delivery.RecipientDelivery;
import org.shem.delivery.RecipientOutcome;
import org.shem.identity.EmailAddress;
import org.shem.identity.IdentityException;
import org.shem.identity.IdentityService;
import org.shem.identity.RecipientRoute;
import org.shem.policy.DnsResolver;
import org.shem.store.DeliveryTarget;
import org.shem.store.SpecialUse;

/**
 * Delivers queued items to remote MX hosts, independent of any user session or mailbox key. For
 * each due item, recipients are grouped by domain; each domain is routed (MX, implicit MX, null
 * MX), checked against its MTA-STS policy, and tried host by host. Per recipient: {@code 2xx} is
 * delivered, {@code 5xx} is a final failure, anything else is retried on the backoff schedule until
 * the item expires. When nothing is pending, failed recipients produce one DSN to the (local)
 * sender through encrypted delivery, and the item is removed.
 *
 * <p>Without an enforced MTA-STS policy, STARTTLS is used when offered without certificate
 * validation (opportunistic, RFC 7435) and a failed handshake falls back to plaintext. DANE is not
 * implemented (ADR 0012).
 */
public final class OutboundDelivery implements AutoCloseable {
  private static final System.Logger LOG = System.getLogger(OutboundDelivery.class.getName());

  private final OutboundQueue queue;
  private final OutboundSettings settings;
  private final MxRouting routing;
  private final MtaSts mtaSts;
  private final DeliveryService local;
  private final IdentityService identity;
  private final SecureRandom random;
  private final Clock clock;
  private final SSLContext opportunistic;
  private final Set<OpaqueId> inFlight = ConcurrentHashMap.newKeySet();
  private final Semaphore slots;
  private final ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
  private final ScheduledExecutorService ticker =
      Executors.newSingleThreadScheduledExecutor(
          Thread.ofPlatform().name("shem-outbound").daemon(true).factory());

  final LongAdder delivered = new LongAdder();
  final LongAdder failed = new LongAdder();
  final LongAdder deferred = new LongAdder();

  OutboundDelivery(
      OutboundQueue queue,
      OutboundSettings settings,
      DnsResolver resolver,
      MtaSts.Fetcher fetcher,
      DeliveryService local,
      IdentityService identity,
      SecureRandom random,
      Clock clock) {
    this.queue = queue;
    this.settings = settings;
    this.routing = new MxRouting(resolver);
    this.mtaSts = new MtaSts(resolver, fetcher, clock);
    this.local = local;
    this.identity = identity;
    this.random = random;
    this.clock = clock;
    this.slots = new Semaphore(settings.maxConcurrent());
    this.opportunistic = unverifiedContext(random);
  }

  /** Production wiring: MTA-STS policies fetched over HTTPS. */
  public static OutboundDelivery create(
      OutboundQueue queue,
      OutboundSettings settings,
      DnsResolver resolver,
      DeliveryService local,
      IdentityService identity,
      SecureRandom random,
      Clock clock) {
    return new OutboundDelivery(
        queue,
        settings,
        resolver,
        new HttpsPolicyFetcher(resolver, settings.connectTimeout()),
        local,
        identity,
        random,
        clock);
  }

  /** Starts periodic processing of due items. */
  public void start(java.time.Duration interval) {
    var unused =
        ticker.scheduleWithFixedDelay(this::runDue, 0, interval.toMillis(), TimeUnit.MILLISECONDS);
  }

  /** Processes every due item once, waiting for completion (used by tests and on shutdown). */
  public void runDueNow() throws InterruptedException {
    List<java.util.concurrent.Future<?>> futures = new ArrayList<>();
    for (QueueItem item : queue.due(clock.instant())) {
      if (inFlight.add(item.id())) {
        futures.add(workers.submit(() -> processGuarded(item.id())));
      }
    }
    for (java.util.concurrent.Future<?> future : futures) {
      try {
        future.get();
      } catch (java.util.concurrent.ExecutionException e) {
        LOG.log(
            System.Logger.Level.ERROR,
            "outbound worker failed: {0}",
            java.util.Objects.requireNonNullElse(e.getCause(), e).getClass().getSimpleName());
      }
    }
  }

  private void runDue() {
    for (QueueItem item : queue.due(clock.instant())) {
      if (inFlight.add(item.id())) {
        try {
          workers.execute(() -> processGuarded(item.id()));
        } catch (java.util.concurrent.RejectedExecutionException e) {
          inFlight.remove(item.id());
        }
      }
    }
  }

  private void processGuarded(OpaqueId id) {
    try {
      slots.acquire();
      try {
        QueueItem item = queue.get(id).orElse(null);
        if (item != null) {
          process(item);
        }
      } finally {
        slots.release();
      }
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    } catch (IOException | RuntimeException e) {
      LOG.log(
          System.Logger.Level.ERROR,
          "outbound processing failed: {0}",
          e.getClass().getSimpleName());
    } finally {
      inFlight.remove(id);
    }
  }

  void process(QueueItem item) throws IOException {
    Instant now = clock.instant();
    if (!item.pending().isEmpty() && now.isAfter(item.expires())) {
      List<QueueItem.Recipient> expired = new ArrayList<>();
      for (QueueItem.Recipient r : item.pending()) {
        expired.add(new QueueItem.Recipient(r.address(), QueueItem.Status.FAILED, "expired"));
      }
      item = item.withRecipients(expired);
      queue.update(item);
    }
    if (!item.pending().isEmpty()) {
      Map<String, List<QueueItem.Recipient>> byDomain = new LinkedHashMap<>();
      for (QueueItem.Recipient r : item.pending()) {
        String domain =
            r.address().substring(r.address().lastIndexOf('@') + 1).toLowerCase(Locale.ROOT);
        byDomain.computeIfAbsent(domain, d -> new ArrayList<>()).add(r);
      }
      List<QueueItem.Recipient> updates = new ArrayList<>();
      for (Map.Entry<String, List<QueueItem.Recipient>> entry : byDomain.entrySet()) {
        List<QueueItem.Recipient> recipients = entry.getValue();
        for (int i = 0; i < recipients.size(); i += settings.maxRecipientsPerTransaction()) {
          updates.addAll(
              deliverDomain(
                  item,
                  entry.getKey(),
                  recipients.subList(
                      i, Math.min(recipients.size(), i + settings.maxRecipientsPerTransaction()))));
        }
      }
      item = item.withRecipients(updates);
      for (QueueItem.Recipient r : updates) {
        switch (r.status()) {
          case DELIVERED -> delivered.increment();
          case FAILED -> failed.increment();
          case PENDING -> deferred.increment();
        }
      }
      if (!item.pending().isEmpty()) {
        int attempts = item.attempts() + 1;
        queue.update(
            item.rescheduled(clock.instant().plus(settings.delayAfter(attempts)), attempts));
        return;
      }
      queue.update(item);
    }
    if (!item.failed().isEmpty() && !item.notified() && !item.sender().isEmpty()) {
      if (!notifySender(item)) {
        int attempts = item.attempts() + 1;
        queue.update(
            item.rescheduled(clock.instant().plus(settings.delayAfter(attempts)), attempts));
        return;
      }
      item = item.markNotified();
      queue.update(item);
    }
    queue.remove(item.id());
  }

  /** Returns the new state of each recipient after trying the domain's hosts. */
  private List<QueueItem.Recipient> deliverDomain(
      QueueItem item, String domain, List<QueueItem.Recipient> recipients) {
    MxRouting.Route route;
    try {
      route = routing.route(domain);
    } catch (DnsResolver.DnsTemporaryException e) {
      return mark(recipients, QueueItem.Status.PENDING, "dns-temperror");
    }
    if (route instanceof MxRouting.NoMail) {
      return mark(recipients, QueueItem.Status.FAILED, "null-mx");
    }
    List<String> hosts = ((MxRouting.Hosts) route).hosts();
    MtaSts.Policy policy = mtaSts.policy(domain);
    boolean enforce = policy != null && policy.mode() == MtaSts.Mode.ENFORCE;
    if (policy != null && enforce) {
      MtaSts.Policy enforced = policy;
      hosts = hosts.stream().filter(enforced::allows).toList();
      if (hosts.isEmpty()) {
        return mark(recipients, QueueItem.Status.PENDING, "mta-sts-no-valid-mx");
      }
    }
    List<QueueItem.Recipient> current = recipients;
    for (String host : hosts) {
      Attempt attempt = attempt(item, host, current, enforce, true);
      if (attempt.tlsFailed() && !enforce) {
        attempt = attempt(item, host, current, false, false);
      }
      if (attempt.completed()) {
        return attempt.results();
      }
      current = attempt.results();
    }
    return current;
  }

  private record Attempt(boolean completed, boolean tlsFailed, List<QueueItem.Recipient> results) {}

  private Attempt attempt(
      QueueItem item,
      String host,
      List<QueueItem.Recipient> recipients,
      boolean requireVerifiedTls,
      boolean tryTls) {
    try (SmtpConnection connection =
        SmtpConnection.open(
            host, settings.port(), settings.connectTimeout(), settings.commandTimeout())) {
      SmtpConnection.Reply greeting = connection.read();
      if (greeting.code() != 220) {
        return new Attempt(
            false, false, mark(recipients, QueueItem.Status.PENDING, greeting.summary()));
      }
      java.util.Set<String> extensions = connection.hello(settings.hostName());
      if (extensions.contains("STARTTLS") && tryTls) {
        try {
          connection.startTls(
              requireVerifiedTls ? settings.verifiedTls() : opportunistic,
              host,
              requireVerifiedTls);
        } catch (IOException e) {
          return new Attempt(false, true, mark(recipients, QueueItem.Status.PENDING, "tls-failed"));
        }
        extensions = connection.hello(settings.hostName());
      } else if (requireVerifiedTls) {
        return new Attempt(
            false, false, mark(recipients, QueueItem.Status.PENDING, "mta-sts-no-tls"));
      }
      SmtpConnection.Reply mail = connection.command("MAIL FROM:<" + item.sender() + ">");
      if (!mail.positive()) {
        QueueItem.Status status =
            mail.permanent() ? QueueItem.Status.FAILED : QueueItem.Status.PENDING;
        return new Attempt(true, false, mark(recipients, status, mail.summary()));
      }
      List<QueueItem.Recipient> results = new ArrayList<>();
      List<QueueItem.Recipient> accepted = new ArrayList<>();
      for (QueueItem.Recipient r : recipients) {
        SmtpConnection.Reply rcpt = connection.command("RCPT TO:<" + r.address() + ">");
        if (rcpt.positive()) {
          accepted.add(r);
        } else {
          results.add(
              new QueueItem.Recipient(
                  r.address(),
                  rcpt.permanent() ? QueueItem.Status.FAILED : QueueItem.Status.PENDING,
                  rcpt.summary()));
        }
      }
      if (accepted.isEmpty()) {
        return new Attempt(true, false, results);
      }
      SmtpConnection.Reply data = connection.command("DATA");
      if (data.code() != 354) {
        QueueItem.Status status =
            data.permanent() ? QueueItem.Status.FAILED : QueueItem.Status.PENDING;
        results.addAll(mark(accepted, status, data.summary()));
        return new Attempt(true, false, results);
      }
      SmtpConnection.Reply end;
      try (InputStream message = queue.openMessage(item.id())) {
        end = connection.data(message, settings.dataTimeout());
      }
      QueueItem.Status status =
          end.positive()
              ? QueueItem.Status.DELIVERED
              : end.permanent() ? QueueItem.Status.FAILED : QueueItem.Status.PENDING;
      results.addAll(mark(accepted, status, end.summary()));
      return new Attempt(true, false, results);
    } catch (IOException e) {
      // Connection or protocol failure: try the next host, or retry later. A failure after the
      // final dot may duplicate the message on the next attempt (unavoidable ambiguity).
      return new Attempt(
          false, false, mark(recipients, QueueItem.Status.PENDING, "connection-failed"));
    }
  }

  private static List<QueueItem.Recipient> mark(
      List<QueueItem.Recipient> recipients, QueueItem.Status status, String reply) {
    List<QueueItem.Recipient> marked = new ArrayList<>();
    for (QueueItem.Recipient r : recipients) {
      marked.add(new QueueItem.Recipient(r.address(), status, reply));
    }
    return marked;
  }

  /** Delivers a DSN to the sender's own mailbox; false if it must be retried. */
  private boolean notifySender(QueueItem item) throws IOException {
    List<RecipientRoute> routes;
    try {
      routes = identity.resolveRecipient(EmailAddress.parse(item.sender()));
    } catch (IdentityException | IllegalArgumentException e) {
      return true; // the sender no longer exists: nobody to notify
    }
    if (routes.isEmpty()) {
      return true;
    }
    byte[] token = new byte[12];
    random.nextBytes(token);
    byte[] dsn;
    try (InputStream original = queue.openMessage(item.id())) {
      dsn =
          Dsn.build(
              settings.hostName(),
              "dsn-" + HexFormat.of().formatHex(token),
              item,
              item.failed(),
              original,
              clock.instant());
    }
    List<RecipientDelivery> recipients = new ArrayList<>();
    for (RecipientRoute route : routes) {
      recipients.add(
          new RecipientDelivery(
              route,
              item.sender(),
              new DeliveryTarget.Role(SpecialUse.INBOX),
              0,
              List.of(),
              List.of("dsn")));
    }
    // The queue item id makes DSN delivery idempotent if the item state update is lost.
    List<RecipientOutcome> outcomes =
        local.deliver(
            new DeliveryRequest(
                item.id(), recipients, MessageSource.ofBytes(dsn), clock.millis(), ""));
    return outcomes.stream().allMatch(o -> o instanceof RecipientOutcome.Delivered);
  }

  public long deliveredCount() {
    return delivered.sum();
  }

  public long failedCount() {
    return failed.sum();
  }

  public long deferredCount() {
    return deferred.sum();
  }

  @Override
  public void close() {
    ticker.shutdownNow();
    workers.shutdown();
    try {
      if (!workers.awaitTermination(30, TimeUnit.SECONDS)) {
        workers.shutdownNow();
      }
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      workers.shutdownNow();
    }
  }

  /**
   * Opportunistic TLS (RFC 7435): encrypts against passive observers without authenticating the
   * peer. Used only when no MTA-STS policy is enforced; enforced connections use {@link
   * OutboundSettings#verifiedTls()}.
   */
  @SuppressWarnings("TrustAllCerts") // deliberate: opportunistic TLS, see ADR 0012
  private static SSLContext unverifiedContext(SecureRandom random) {
    X509TrustManager any =
        new X509TrustManager() {
          @Override
          public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String type) {}

          @Override
          public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String type) {}

          @Override
          public java.security.cert.X509Certificate[] getAcceptedIssuers() {
            return new java.security.cert.X509Certificate[0];
          }
        };
    try {
      SSLContext context = SSLContext.getInstance("TLS");
      context.init(null, new TrustManager[] {any}, random);
      return context;
    } catch (java.security.GeneralSecurityException e) {
      throw new IllegalStateException("TLS unavailable", e);
    }
  }
}
