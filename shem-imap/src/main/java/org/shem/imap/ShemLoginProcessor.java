package org.shem.imap;

import java.util.List;
import org.apache.james.imap.api.display.HumanReadableText;
import org.apache.james.imap.api.message.Capability;
import org.apache.james.imap.api.message.response.StatusResponseFactory;
import org.apache.james.imap.api.process.ImapSession;
import org.apache.james.imap.message.request.LoginRequest;
import org.apache.james.imap.processor.AbstractMailboxProcessor;
import org.apache.james.imap.processor.CapabilityImplementingProcessor;
import org.apache.james.mailbox.MailboxManager;
import org.apache.james.metrics.api.MetricFactory;
import org.apache.james.util.MDCBuilder;

/** IMAP LOGIN through Shem's shared authenticator; refused before TLS. */
final class ShemLoginProcessor extends AbstractMailboxProcessor<LoginRequest>
    implements CapabilityImplementingProcessor {
  private static final List<Capability> LOGINDISABLED = List.of(Capability.of("LOGINDISABLED"));
  private final ImapAuthentication authentication;

  ShemLoginProcessor(
      MailboxManager mailboxManager,
      StatusResponseFactory factory,
      MetricFactory metrics,
      ImapAuthentication authentication) {
    super(LoginRequest.class, mailboxManager, factory, metrics);
    this.authentication = authentication;
  }

  @Override
  protected void processRequest(LoginRequest request, ImapSession session, Responder responder) {
    if (session.isPlainAuthDisallowed()) {
      no(request, responder, HumanReadableText.DISABLED_LOGIN);
      return;
    }
    ImapAuthentication.Result result =
        authentication.authenticate(session, request.getUserid().asString(), request.getPassword());
    respond(request, session, responder, result);
  }

  private void respond(
      org.apache.james.imap.api.message.request.ImapRequest request,
      ImapSession session,
      Responder responder,
      ImapAuthentication.Result result) {
    switch (result) {
      case OK -> okComplete(request, responder);
      case TOO_MANY_FAILURES -> {
        no(request, responder, ImapAuthentication.text(result));
        bye(responder);
        session.logout().block();
      }
      default -> no(request, responder, ImapAuthentication.text(result));
    }
  }

  @Override
  public List<Capability> getImplementedCapabilities(ImapSession session) {
    return session.isPlainAuthDisallowed() ? LOGINDISABLED : List.of();
  }

  @Override
  protected MDCBuilder mdc(LoginRequest request) {
    // Deliberately no user name: logs and MDC must not contain addresses.
    return MDCBuilder.create().addToContext(MDCBuilder.ACTION, "LOGIN");
  }
}
