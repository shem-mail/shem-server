package org.shem.imap;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import java.util.Set;
import org.apache.james.imap.api.process.ImapProcessor;
import org.apache.james.imap.api.process.ImapSession;
import org.apache.james.imap.decode.ImapDecoder;
import org.apache.james.imap.encode.ImapEncoder;
import org.apache.james.imapserver.netty.IMAPServer;
import org.apache.james.imapserver.netty.ImapMetrics;
import org.apache.james.imapserver.netty.NettyConstants;
import org.apache.james.metrics.api.NoopGaugeRegistry;
import org.apache.james.protocols.api.ClientAuth;
import org.apache.james.protocols.netty.Encryption;
import org.shem.mailbox.MailboxLease;
import org.shem.tls.ReloadableTlsContext;

/**
 * James's Netty IMAP server with three Shem changes: TLS comes from the reloadable listener context
 * (implicit TLS only), no JMX beans are registered, and the session's unlock lease is released when
 * the connection closes for any reason (LOGOUT, disconnect, timeout).
 */
@SuppressWarnings("unchecked") // raw return type inherited from IMAPServer.createPipelineFactory()
final class ShemImapServer extends IMAPServer {
  private static final String[] PROTOCOLS = {"TLSv1.3", "TLSv1.2"};
  private final ReloadableTlsContext tls;

  ShemImapServer(
      ImapDecoder decoder,
      ImapEncoder encoder,
      ImapProcessor processor,
      AggregateMetrics metrics,
      ReloadableTlsContext tls) {
    super(decoder, encoder, processor, new ImapMetrics(metrics), new NoopGaugeRegistry(), Set.of());
    this.tls = tls;
  }

  @Override
  protected void buildSSLContext() {
    encryption = Encryption.createTls(tls.sslContext(), null, PROTOCOLS, ClientAuth.NONE);
  }

  @Override
  protected void registerMBean() {
    // No JMX: connection descriptions would expose user names.
  }

  @Override
  protected void unregisterMBean() {}

  @Override
  protected ChannelInboundHandlerAdapter createCoreHandler() {
    return new LeaseReleasingHandler(super.createCoreHandler());
  }

  /** Delegates to James's core handler and closes the lease when the channel goes inactive. */
  private static final class LeaseReleasingHandler extends ChannelInboundHandlerAdapter {
    private final ChannelInboundHandlerAdapter delegate;

    LeaseReleasingHandler(ChannelInboundHandlerAdapter delegate) {
      this.delegate = delegate;
    }

    @Override
    public void handlerAdded(ChannelHandlerContext ctx) throws Exception {
      delegate.handlerAdded(ctx);
    }

    @Override
    public void handlerRemoved(ChannelHandlerContext ctx) throws Exception {
      delegate.handlerRemoved(ctx);
    }

    @Override
    public void channelRegistered(ChannelHandlerContext ctx) throws Exception {
      delegate.channelRegistered(ctx);
    }

    @Override
    public void channelUnregistered(ChannelHandlerContext ctx) throws Exception {
      delegate.channelUnregistered(ctx);
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
      delegate.channelActive(ctx);
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
      ImapSession session = ctx.channel().attr(NettyConstants.IMAP_SESSION_ATTRIBUTE_KEY).get();
      MailboxLease lease =
          session == null ? null : Sessions.leaseOrNull(session.getMailboxSession());
      try {
        delegate.channelInactive(ctx);
      } finally {
        if (lease != null) {
          lease.close();
        }
      }
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
      delegate.channelRead(ctx, msg);
    }

    @Override
    public void channelReadComplete(ChannelHandlerContext ctx) throws Exception {
      delegate.channelReadComplete(ctx);
    }

    @Override
    public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
      delegate.userEventTriggered(ctx, evt);
    }

    @Override
    public void channelWritabilityChanged(ChannelHandlerContext ctx) throws Exception {
      delegate.channelWritabilityChanged(ctx);
    }

    @Override
    @SuppressWarnings("deprecation") // Netty still routes exceptions through this method
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
      delegate.exceptionCaught(ctx, cause);
    }
  }
}
