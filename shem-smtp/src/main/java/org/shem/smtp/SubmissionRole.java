package org.shem.smtp;

import java.net.InetSocketAddress;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import org.apache.james.protocols.api.ClientAuth;
import org.apache.james.protocols.api.handler.CommandDispatcher;
import org.apache.james.protocols.api.handler.ProtocolHandler;
import org.apache.james.protocols.netty.AllButStartTlsLineChannelHandlerFactory;
import org.apache.james.protocols.netty.Encryption;
import org.apache.james.protocols.netty.NettyServer;
import org.apache.james.protocols.smtp.SMTPProtocolHandlerChain;
import org.apache.james.protocols.smtp.SMTPSession;
import org.apache.james.protocols.smtp.core.DataLineMessageHookHandler;
import org.apache.james.protocols.smtp.core.HeloCmdHandler;
import org.apache.james.protocols.smtp.core.MailCmdHandler;
import org.apache.james.protocols.smtp.core.NoopCmdHandler;
import org.apache.james.protocols.smtp.core.QuitCmdHandler;
import org.apache.james.protocols.smtp.core.RcptCmdHandler;
import org.apache.james.protocols.smtp.core.RsetCmdHandler;
import org.apache.james.protocols.smtp.core.UnknownCmdHandler;
import org.apache.james.protocols.smtp.core.WelcomeMessageHandler;
import org.apache.james.protocols.smtp.core.esmtp.EhloCmdHandler;
import org.apache.james.protocols.smtp.core.esmtp.StartTlsCmdHandler;
import org.jspecify.annotations.Nullable;
import org.shem.common.IdGenerator;
import org.shem.delivery.DeliveryService;
import org.shem.identity.IdentityService;
import org.shem.mailbox.SessionService;
import org.shem.tls.ReloadableTlsContext;

/**
 * Authenticated submission (ADR 0011): port 465 with implicit TLS and port 587 with STARTTLS
 * required before AUTH. Local recipients only; no plaintext outbound queue exists yet.
 */
public final class SubmissionRole implements AutoCloseable {
  private static final String[] PROTOCOLS = {"TLSv1.3", "TLSv1.2"};

  private final List<NettyServer> servers;
  private final @Nullable NettyServer implicitTls;
  private final @Nullable NettyServer startTls;

  private SubmissionRole(
      List<NettyServer> servers,
      @Nullable NettyServer implicitTls,
      @Nullable NettyServer startTls) {
    this.servers = List.copyOf(servers);
    this.implicitTls = implicitTls;
    this.startTls = startTls;
  }

  public static SubmissionRole start(
      SubmissionSettings settings,
      SessionService sessions,
      IdentityService identity,
      DeliveryService delivery,
      ReloadableTlsContext tls,
      IdGenerator ids,
      SecureRandom random,
      Clock clock)
      throws Exception {
    InboundSmtpRole.sweepSpool(settings.spoolDirectory());
    SendRate rate = new SendRate(settings.recipientsPerHour(), clock);
    List<NettyServer> servers = new ArrayList<>();
    NettyServer implicit = null;
    NettyServer starttls = null;
    try {
      InetSocketAddress implicitBind = settings.implicitTls();
      if (implicitBind != null) {
        implicit =
            server(
                settings.data(implicitBind),
                Encryption.createTls(tls.sslContext(), null, PROTOCOLS, ClientAuth.NONE),
                sessions,
                identity,
                delivery,
                rate,
                ids,
                random,
                clock);
        servers.add(implicit);
      }
      InetSocketAddress startTlsBind = settings.startTls();
      if (startTlsBind != null) {
        starttls =
            server(
                settings.data(startTlsBind),
                Encryption.createStartTls(tls.sslContext(), null, PROTOCOLS, ClientAuth.NONE),
                sessions,
                identity,
                delivery,
                rate,
                ids,
                random,
                clock);
        servers.add(starttls);
      }
    } catch (Exception | Error e) {
      servers.forEach(NettyServer::unbind);
      throw e;
    }
    return new SubmissionRole(servers, implicit, starttls);
  }

  private static NettyServer server(
      InboundSettings settings,
      Encryption encryption,
      SessionService sessions,
      IdentityService identity,
      DeliveryService delivery,
      SendRate rate,
      IdGenerator ids,
      SecureRandom random,
      Clock clock)
      throws Exception {
    TimerMetrics timers = new TimerMetrics();
    InboundMetrics metrics = new InboundMetrics();
    SMTPProtocolHandlerChain chain = new SMTPProtocolHandlerChain(timers, false);
    List<ProtocolHandler> handlers = new ArrayList<>();
    handlers.add(new CommandDispatcher<SMTPSession>());
    handlers.add(new EhloCmdHandler(timers));
    handlers.add(new HeloCmdHandler(timers));
    handlers.add(new SubmissionAuth(sessions));
    handlers.add(new MailCmdHandler(timers));
    handlers.add(new RcptCmdHandler(timers));
    handlers.add(new ShemDataCmdHandler(timers, settings, random));
    handlers.add(new RsetCmdHandler());
    handlers.add(new NoopCmdHandler());
    handlers.add(new QuitCmdHandler(timers));
    if (encryption.isStartTLS()) {
      handlers.add(new StartTlsCmdHandler());
    }
    handlers.add(new UnknownCmdHandler(timers));
    handlers.add(new WelcomeMessageHandler());
    handlers.add(new SizeLimit(settings.maxMessageBytes(), metrics));
    handlers.add(new TraceHeaders(settings.hostName(), clock, true));
    handlers.add(new DataLineMessageHookHandler());
    handlers.add(new SubmissionHooks(identity, rate, settings.maxRecipients()));
    handlers.add(new SubmissionDelivery(delivery, identity, ids, clock));
    handlers.add(new EnvelopeCleanup());
    chain.addAll(handlers);
    chain.wireExtensibleHandlers();
    NettyServer server =
        new NettyServer.Factory()
            .protocol(new ShemSmtpProtocol(chain, new ShemSmtpConfiguration(settings)))
            .secure(encryption)
            .frameHandlerFactory(
                new AllButStartTlsLineChannelHandlerFactory(
                    "starttls", InboundSmtpRole.MAX_LINE_BYTES))
            .build();
    server.setListenAddresses(settings.bind());
    server.setTimeout(settings.timeoutSeconds());
    server.setMaxConcurrentConnections(settings.maxConnections());
    server.setMaxConcurrentConnectionsPerIP(settings.maxConnectionsPerIp());
    server.bind();
    return server;
  }

  /** Port of the implicit-TLS listener, or -1. */
  public int implicitTlsPort() {
    NettyServer server = implicitTls;
    return server == null ? -1 : server.getListenAddresses().getFirst().getPort();
  }

  /** Port of the STARTTLS listener, or -1. */
  public int startTlsPort() {
    NettyServer server = startTls;
    return server == null ? -1 : server.getListenAddresses().getFirst().getPort();
  }

  @Override
  public void close() {
    servers.forEach(NettyServer::unbind);
  }
}
