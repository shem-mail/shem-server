package org.shem.smtp;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
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
import org.shem.common.DurableFiles;
import org.shem.common.IdGenerator;
import org.shem.delivery.DeliveryService;
import org.shem.identity.IdentityService;
import org.shem.policy.Greylist;
import org.shem.policy.InboundPolicy;
import org.shem.tls.ReloadableTlsContext;

/**
 * The inbound MX listener (ADR 0009). Opportunistic STARTTLS, no AUTH, no relay, no VRFY/EXPN. Uses
 * only James's protocol handlers and Netty transport; message hooks are Shem's own.
 */
public final class InboundSmtpRole implements AutoCloseable {
  private static final String[] PROTOCOLS = {"TLSv1.3", "TLSv1.2"};

  /**
   * Room above {@code message.maxBytes} that delivery must allow for the trace and policy fields
   * this role prepends.
   */
  public static final long HEADER_ALLOWANCE = 64 * 1024;

  /** RFC 5321 allows 1000-octet lines; accept more from lenient senders, but stay bounded. */
  static final int MAX_LINE_BYTES = 8192;

  private final NettyServer server;
  private final InboundMetrics metrics;

  private InboundSmtpRole(NettyServer server, InboundMetrics metrics) {
    this.server = server;
    this.metrics = metrics;
  }

  public static InboundSmtpRole start(
      InboundSettings settings,
      IdentityService identity,
      DeliveryService delivery,
      InboundPolicy policy,
      @Nullable Greylist greylist,
      ReloadableTlsContext tls,
      IdGenerator ids,
      SecureRandom random,
      Clock clock)
      throws Exception {
    sweepSpool(settings.spoolDirectory());
    InboundMetrics metrics = new InboundMetrics();
    TimerMetrics timers = new TimerMetrics();
    SMTPProtocolHandlerChain chain = new SMTPProtocolHandlerChain(timers, false);
    List<ProtocolHandler> handlers =
        List.of(
            new CommandDispatcher<SMTPSession>(),
            new EhloCmdHandler(timers),
            new HeloCmdHandler(timers),
            new MailCmdHandler(timers),
            new RcptCmdHandler(timers),
            new ShemDataCmdHandler(timers, settings, random),
            new RsetCmdHandler(),
            new NoopCmdHandler(),
            new QuitCmdHandler(timers),
            new StartTlsCmdHandler(),
            new UnknownCmdHandler(timers),
            new WelcomeMessageHandler(),
            new SizeLimit(settings.maxMessageBytes(), metrics),
            new TraceHeaders(settings.hostName(), clock, false),
            new DataLineMessageHookHandler(),
            new RecipientPolicy(
                identity,
                settings.maxRecipients(),
                settings.maxUnknownRecipients(),
                metrics,
                greylist),
            new DeliveryHook(delivery, policy, ids, clock, metrics),
            new EnvelopeCleanup());
    chain.addAll(handlers);
    chain.wireExtensibleHandlers();
    NettyServer server =
        new NettyServer.Factory()
            .protocol(new ShemSmtpProtocol(chain, new ShemSmtpConfiguration(settings)))
            .secure(Encryption.createStartTls(tls.sslContext(), null, PROTOCOLS, ClientAuth.NONE))
            .frameHandlerFactory(
                new AllButStartTlsLineChannelHandlerFactory("starttls", MAX_LINE_BYTES))
            .build();
    server.setListenAddresses(settings.bind());
    server.setTimeout(settings.timeoutSeconds());
    server.setMaxConcurrentConnections(settings.maxConnections());
    server.setMaxConcurrentConnectionsPerIP(settings.maxConnectionsPerIp());
    server.bind();
    return new InboundSmtpRole(server, metrics);
  }

  /**
   * Removes provisional files left by a crash. Their keys existed only in the crashed process, so
   * they are unreadable; none of them was acknowledged to a client.
   */
  static void sweepSpool(Path directory) throws IOException {
    DurableFiles.createPrivateDirectories(directory);
    try (DirectoryStream<Path> files = Files.newDirectoryStream(directory)) {
      for (Path file : files) {
        Files.deleteIfExists(file);
      }
    }
  }

  public int port() {
    InetSocketAddress address = server.getListenAddresses().getFirst();
    return address.getPort();
  }

  public InboundMetrics metrics() {
    return metrics;
  }

  @Override
  public void close() {
    server.unbind();
  }
}
