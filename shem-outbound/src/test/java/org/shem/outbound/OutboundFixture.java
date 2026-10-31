package org.shem.outbound;

import java.io.IOException;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import javax.net.ssl.SSLContext;
import org.shem.common.FaultInjector;
import org.shem.common.IdGenerator;
import org.shem.common.OpaqueId;
import org.shem.crypto.Argon2Parameters;
import org.shem.crypto.Argon2idKdf;
import org.shem.crypto.KdfAdmission;
import org.shem.delivery.DeliveryService;
import org.shem.identity.DeliveryPolicy;
import org.shem.identity.EmailAddress;
import org.shem.identity.IdentityService;
import org.shem.identity.QuotaLedger;
import org.shem.mailbox.MailboxProvisioning;
import org.shem.policy.DnsResolver;
import org.shem.store.BlobStore;
import org.shem.store.MailboxPaths;
import org.shem.store.ReceiptStore;
import org.shem.store.metadata.MetadataStore;

/** Queue, delivery worker, local encrypted delivery (for DSNs), fake DNS, and a test clock. */
final class OutboundFixture {
  static final SecureRandom RANDOM = new SecureRandom();
  static final String SENDER = "alice@example.org";

  static final class MutableClock extends Clock {
    volatile Instant now = Instant.parse("2026-10-25T10:00:00Z");

    @Override
    public ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      return now;
    }
  }

  final MutableClock clock = new MutableClock();
  final Map<String, List<String>> dns = new ConcurrentHashMap<>();
  final Map<String, String> policies = new ConcurrentHashMap<>();
  final List<OpaqueId> localDeliveries = new CopyOnWriteArrayList<>();
  final IdentityService identity;
  final DeliveryService local;
  final OutboundQueue queue;
  final Path root;
  final OpaqueId senderMailbox;

  OutboundFixture(Path root) throws Exception {
    this.root = root;
    IdGenerator ids = IdGenerator.secure(RANDOM);
    MailboxPaths paths = new MailboxPaths(root.resolve("mailboxes"));
    identity =
        IdentityService.open(
            root.resolve("routing/directory.bin"),
            clock,
            ids,
            DeliveryPolicy.DEFAULT,
            Duration.ofDays(30));
    local =
        new DeliveryService(
            new BlobStore(paths, ids, RANDOM, FaultInjector.NONE),
            new ReceiptStore(paths, ids, RANDOM, clock, FaultInjector.NONE),
            new QuotaLedger(paths::mailbox),
            localDeliveries::add,
            10 << 20);
    identity.createDomain("example.org");
    Argon2Parameters cheap = new Argon2Parameters(64, 1, 1);
    MailboxProvisioning provisioning =
        new MailboxProvisioning(
            identity,
            paths,
            new Argon2idKdf(
                new KdfAdmission(1 << 20, Duration.ofSeconds(5)),
                new Argon2Parameters.Limits(8, 1 << 20, 10, 8)),
            cheap,
            new MetadataStore.Environment(
                ids, RANDOM, clock, FaultInjector.NONE, MetadataStore.Options.DEFAULT),
            ids,
            RANDOM,
            clock);
    MailboxProvisioning.Provisioned alice =
        provisioning.provision(EmailAddress.parse(SENDER), 0, Duration.ofDays(1));
    alice.bootstrapPassword().close();
    senderMailbox = alice.account().mailboxId();
    queue = openQueue();
  }

  OutboundQueue openQueue() throws IOException {
    return OutboundQueue.open(
        root.resolve("queue"),
        new OutboundQueue.Limits(100, 10 << 20, Duration.ofDays(5)),
        IdGenerator.secure(RANDOM),
        clock);
  }

  DnsResolver resolver() {
    return (name, type) -> {
      if (dns.containsKey("FAIL " + name)) {
        throw new DnsResolver.DnsTemporaryException("simulated");
      }
      return dns.getOrDefault(name + "/" + type, List.of());
    };
  }

  OutboundDelivery delivery(OutboundQueue q, int port, SSLContext verified) {
    return new OutboundDelivery(
        q,
        new OutboundSettings(
            "mx.example.org",
            port,
            Duration.ofSeconds(5),
            Duration.ofSeconds(10),
            Duration.ofSeconds(10),
            verified,
            OutboundSettings.DEFAULT_RETRIES,
            4,
            50),
        resolver(),
        domain -> {
          String policy = policies.get(domain);
          if (policy == null) {
            throw new IOException("no policy");
          }
          return policy;
        },
        local,
        identity,
        RANDOM,
        clock);
  }
}
