package org.shem.imap;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import org.apache.james.imap.api.display.HumanReadableText;
import org.apache.james.imap.api.message.Capability;
import org.apache.james.imap.api.message.request.ImapRequest;
import org.apache.james.imap.api.message.response.StatusResponseFactory;
import org.apache.james.imap.api.process.ImapSession;
import org.apache.james.imap.message.request.AuthenticateRequest;
import org.apache.james.imap.message.request.IRAuthenticateRequest;
import org.apache.james.imap.message.response.AuthenticateResponse;
import org.apache.james.imap.processor.AbstractMailboxProcessor;
import org.apache.james.imap.processor.CapabilityImplementingProcessor;
import org.apache.james.mailbox.MailboxManager;
import org.apache.james.metrics.api.MetricFactory;
import org.apache.james.util.MDCBuilder;
import org.apache.james.util.ReactorUtils;
import org.jspecify.annotations.Nullable;
import reactor.core.publisher.Mono;

/**
 * AUTHENTICATE PLAIN (with SASL-IR) only. SCRAM/CRAM cannot work because the server must derive the
 * key-encryption key from the password; OAuth is not offered. Authorization identities other than
 * the authentication identity are refused.
 */
final class ShemAuthenticateProcessor extends AbstractMailboxProcessor<AuthenticateRequest>
    implements CapabilityImplementingProcessor {
  private static final List<Capability> CAPABILITIES =
      List.of(Capability.of("AUTH=PLAIN"), Capability.of("SASL-IR"));
  private final ImapAuthentication authentication;

  ShemAuthenticateProcessor(
      MailboxManager mailboxManager,
      StatusResponseFactory factory,
      MetricFactory metrics,
      ImapAuthentication authentication) {
    super(AuthenticateRequest.class, mailboxManager, factory, metrics);
    this.authentication = authentication;
  }

  @Override
  public List<Class<? extends AuthenticateRequest>> acceptableClasses() {
    return List.of(AuthenticateRequest.class, IRAuthenticateRequest.class);
  }

  @Override
  protected void processRequest(
      AuthenticateRequest request, ImapSession session, Responder responder) {
    if (!request.getAuthType().equalsIgnoreCase("PLAIN")) {
      no(request, responder, HumanReadableText.UNSUPPORTED_AUTHENTICATION_MECHANISM);
      return;
    }
    if (session.isPlainAuthDisallowed()) {
      no(request, responder, HumanReadableText.DISABLED_LOGIN);
      return;
    }
    if (request instanceof IRAuthenticateRequest ir) {
      plain(ir.getInitialClientResponse(), request, session, responder);
      return;
    }
    session.executeSafely(
        () -> {
          responder.respond(new AuthenticateResponse());
          responder.flush();
          session.pushLineHandler(
              (requestSession, data) ->
                  Mono.fromRunnable(
                          () -> {
                            requestSession.popLineHandler();
                            plain(lineOf(data), request, requestSession, responder);
                            responder.flush();
                          })
                      .subscribeOn(ReactorUtils.BLOCKING_CALL_WRAPPER)
                      .then());
        });
  }

  private void plain(String base64, ImapRequest request, ImapSession session, Responder responder) {
    String[] parts = decode(base64);
    if (parts == null) {
      no(request, responder, HumanReadableText.AUTHENTICATION_FAILED);
      return;
    }
    respond(request, session, responder, authentication.authenticate(session, parts[0], parts[1]));
  }

  /** RFC 4616: [authzid] NUL authcid NUL passwd; authzid must be empty or equal authcid. */
  static String @Nullable [] decode(String base64) {
    byte[] raw;
    try {
      raw = Base64.getDecoder().decode(base64.trim());
    } catch (IllegalArgumentException e) {
      return null;
    }
    String text = new String(raw, StandardCharsets.UTF_8);
    java.util.Arrays.fill(raw, (byte) 0);
    int first = text.indexOf('\0');
    int second = first < 0 ? -1 : text.indexOf('\0', first + 1);
    if (first < 0 || second < 0 || text.indexOf('\0', second + 1) >= 0) {
      return null;
    }
    String authzid = text.substring(0, first);
    String authcid = text.substring(first + 1, second);
    String password = text.substring(second + 1);
    if (authcid.isEmpty()
        || password.isEmpty()
        || (!authzid.isEmpty() && !authzid.equals(authcid))) {
      return null;
    }
    return new String[] {authcid, password};
  }

  private static String lineOf(byte[] data) {
    String line = new String(data, StandardCharsets.US_ASCII);
    return line.endsWith("\r\n") ? line.substring(0, line.length() - 2) : line.trim();
  }

  void respond(
      ImapRequest request,
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
    return session.isPlainAuthDisallowed() ? List.of() : CAPABILITIES;
  }

  @Override
  protected MDCBuilder mdc(AuthenticateRequest request) {
    return MDCBuilder.create().addToContext(MDCBuilder.ACTION, "AUTHENTICATE");
  }
}
