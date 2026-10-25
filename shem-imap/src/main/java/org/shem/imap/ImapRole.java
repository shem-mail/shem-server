package org.shem.imap;

import java.net.InetSocketAddress;
import org.apache.commons.configuration2.BaseHierarchicalConfiguration;
import org.apache.james.events.EventBus;
import org.apache.james.events.InVMEventBus;
import org.apache.james.events.MemoryEventDeadLetters;
import org.apache.james.events.RetryBackoffConfiguration;
import org.apache.james.events.delivery.InVmEventDelivery;
import org.apache.james.imap.api.process.ImapProcessor;
import org.apache.james.imap.encode.main.DefaultImapEncoderFactory;
import org.apache.james.imap.encode.main.DefaultLocalizer;
import org.apache.james.imap.main.DefaultImapDecoderFactory;
import org.shem.mailbox.SessionService;
import org.shem.tls.ReloadableTlsContext;

/**
 * The IMAP listener role: composes the James protocol stack over Shem's mailbox services.
 *
 * <p>Plaintext-safety configuration (ADR 0005): literals up to {@code maxMessageBytes} stay in
 * memory ({@code inMemorySizeLimit == literalSizeLimit}), so James never spills them to its temp
 * file; connection counts bound that memory. Credentials are accepted only over TLS.
 */
public final class ImapRole implements AutoCloseable {
  /** Listener settings. */
  public record Settings(
      InetSocketAddress bind,
      String hostName,
      int maxConnections,
      int maxConnectionsPerIp,
      int maxMessageBytes,
      int timeoutSeconds) {}

  private final ShemImapServer server;

  private ImapRole(ShemImapServer server) {
    this.server = server;
  }

  public static ImapRole start(Settings settings, SessionService sessions, ReloadableTlsContext tls)
      throws Exception {
    AggregateMetrics metrics = new AggregateMetrics();
    EventBus eventBus =
        new InVMEventBus(
            new InVmEventDelivery(metrics),
            RetryBackoffConfiguration.DEFAULT,
            new MemoryEventDeadLetters());
    EventPublisher events = new EventPublisher(eventBus);
    ShemMailboxManager manager = new ShemMailboxManager(events);
    ImapProcessor processor =
        ImapProcessors.create(manager, eventBus, new ImapAuthentication(sessions, events), metrics);
    ShemImapServer server =
        new ShemImapServer(
            new DefaultImapDecoderFactory().buildImapDecoder(),
            DefaultImapEncoderFactory.createDefaultEncoder(new DefaultLocalizer(), false),
            processor,
            metrics,
            tls);
    server.configure(configuration(settings));
    server.init();
    return new ImapRole(server);
  }

  static BaseHierarchicalConfiguration configuration(Settings s) {
    BaseHierarchicalConfiguration c = new BaseHierarchicalConfiguration();
    c.addProperty("bind", s.bind().getHostString() + ":" + s.bind().getPort());
    c.addProperty("helloName", s.hostName());
    c.addProperty("helloName.[@autodetect]", false);
    c.addProperty("connectionLimit", s.maxConnections());
    c.addProperty("connectionLimitPerIP", s.maxConnectionsPerIp());
    c.addProperty("timeout", s.timeoutSeconds());
    c.addProperty("literalSizeLimit", s.maxMessageBytes());
    c.addProperty("inMemorySizeLimit", s.maxMessageBytes());
    c.addProperty("plainAuthDisallowed", true);
    c.addProperty("auth.requireSSL", true);
    c.addProperty("auth.plainAuthEnabled", true);
    c.addProperty("provisionDefaultMailboxes", false);
    c.addProperty("enableIdle", true);
    c.addProperty("compress", false);
    c.addProperty(
        "disabledCaps", "CONDSTORE|QRESYNC|OBJECTID|SAVEDATE|UIDONLY|PARTIAL|LIST-STATUS");
    return c;
  }

  public int port() {
    return server.getPort();
  }

  @Override
  public void close() {
    server.destroy();
  }
}
