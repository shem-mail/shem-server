package org.shem.smtp;

import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import org.apache.james.core.Username;
import org.apache.james.protocols.api.ProtocolSession;
import org.apache.james.protocols.api.Request;
import org.apache.james.protocols.api.Response;
import org.apache.james.protocols.api.handler.CommandHandler;
import org.apache.james.protocols.api.handler.LineHandler;
import org.apache.james.protocols.smtp.SMTPResponse;
import org.apache.james.protocols.smtp.SMTPRetCode;
import org.apache.james.protocols.smtp.SMTPSession;
import org.apache.james.protocols.smtp.core.esmtp.EhloExtension;
import org.jspecify.annotations.Nullable;
import org.shem.mailbox.AuthenticationException;
import org.shem.mailbox.Capability;
import org.shem.mailbox.MailboxLease;
import org.shem.mailbox.SessionService;

/**
 * AUTH PLAIN and LOGIN (RFC 4954) through the shared {@link SessionService}: the same key-slot
 * unwrap, per-source limiter, and KDF admission as IMAP. Replaces James's handler, which accepts
 * AUTH without TLS, passes passwords as strings, and logs user names. AUTH is advertised and
 * accepted only after TLS; the authorization identity must be empty or equal the authentication
 * identity. The resulting lease is held until the connection closes and is checked on every
 * transaction.
 */
final class SubmissionAuth implements CommandHandler<SMTPSession>, EhloExtension {
  static final int MAX_FAILURES_PER_CONNECTION = 3;
  private static final Response ENCRYPTION_REQUIRED =
      new SMTPResponse("538", "5.7.11 Encryption required for requested authentication mechanism")
          .immutable();
  private static final Response ALREADY =
      new SMTPResponse(SMTPRetCode.BAD_SEQUENCE, "5.5.1 Already authenticated").immutable();
  private static final Response UNSUPPORTED =
      new SMTPResponse("504", "5.5.4 Unrecognized authentication type").immutable();
  private static final Response SYNTAX =
      new SMTPResponse(SMTPRetCode.SYNTAX_ERROR_ARGUMENTS, "5.5.2 Invalid authentication data")
          .immutable();
  private static final Response CANCELLED =
      new SMTPResponse(SMTPRetCode.SYNTAX_ERROR_ARGUMENTS, "5.0.0 Authentication cancelled")
          .immutable();
  private static final Response FAILED =
      new SMTPResponse(SMTPRetCode.AUTH_FAILED, "5.7.8 Authentication credentials invalid")
          .immutable();
  private static final Response UNAVAILABLE =
      new SMTPResponse(SMTPRetCode.AUTH_TEMPORARY_ERROR, "4.7.0 Temporary authentication failure")
          .immutable();
  private static final Response OK =
      new SMTPResponse(SMTPRetCode.AUTH_OK, "2.7.0 Authentication successful").immutable();
  private static final Response TOO_MANY;

  static {
    SMTPResponse response =
        new SMTPResponse(
            SMTPRetCode.SERVICE_NOT_AVAILABLE, "4.7.0 Too many failed authentications");
    response.setEndSession(true);
    TOO_MANY = response.immutable();
  }

  static final ProtocolSession.AttachmentKey<MailboxLease> LEASE =
      ProtocolSession.AttachmentKey.of("shem.lease", MailboxLease.class);
  private static final ProtocolSession.AttachmentKey<Integer> FAILURES =
      ProtocolSession.AttachmentKey.of("shem.authFailures", Integer.class);

  private final SessionService sessions;

  SubmissionAuth(SessionService sessions) {
    this.sessions = sessions;
  }

  @Override
  public Collection<String> getImplCommands() {
    return List.of("AUTH");
  }

  @Override
  public List<String> getImplementedEsmtpFeatures(SMTPSession session) {
    return session.isTLSStarted() ? List.of("AUTH PLAIN LOGIN") : List.of();
  }

  /** The valid lease of an authenticated session, if any. */
  static @Nullable MailboxLease lease(SMTPSession session) {
    return session
        .getAttachment(LEASE, ProtocolSession.State.Connection)
        .filter(MailboxLease::isValid)
        .orElse(null);
  }

  @Override
  public Response onCommand(SMTPSession session, Request request) {
    if (!session.isTLSStarted()) {
      return ENCRYPTION_REQUIRED;
    }
    if (session.getAttachment(LEASE, ProtocolSession.State.Connection).isPresent()) {
      return ALREADY;
    }
    String argument = request.getArgument() == null ? "" : request.getArgument().strip();
    int space = argument.indexOf(' ');
    String mechanism =
        (space < 0 ? argument : argument.substring(0, space)).toUpperCase(Locale.ROOT);
    @Nullable String initial = space < 0 ? null : argument.substring(space + 1).strip();
    return switch (mechanism) {
      case "PLAIN" -> {
        if (initial != null && !initial.equals("=")) {
          yield plain(session, initial);
        }
        session.pushLineHandler(continuation(line -> plain(session, line)));
        yield new SMTPResponse(SMTPRetCode.AUTH_READY, "");
      }
      case "LOGIN" -> {
        if (initial != null) {
          yield loginUser(session, initial);
        }
        session.pushLineHandler(continuation(line -> loginUser(session, line)));
        yield new SMTPResponse(SMTPRetCode.AUTH_READY, "VXNlcm5hbWU6");
      }
      default -> UNSUPPORTED;
    };
  }

  private interface Step {
    Response on(String line);
  }

  /** A one-line continuation; "*" cancels (RFC 4954 section 4). */
  private static LineHandler<SMTPSession> continuation(Step step) {
    return (session, bytes) -> {
      session.popLineHandler();
      String line = new String(bytes, StandardCharsets.US_ASCII).strip();
      try {
        return line.equals("*") ? CANCELLED : step.on(line);
      } finally {
        Arrays.fill(bytes, (byte) 0);
      }
    };
  }

  private Response loginUser(SMTPSession session, String encodedUser) {
    byte[] user = decode(encodedUser);
    if (user == null) {
      return SYNTAX;
    }
    String username = new String(user, StandardCharsets.UTF_8);
    session.pushLineHandler(continuation(line -> loginPassword(session, username, line)));
    return new SMTPResponse(SMTPRetCode.AUTH_READY, "UGFzc3dvcmQ6");
  }

  private Response loginPassword(SMTPSession session, String username, String encodedPassword) {
    byte[] password = decode(encodedPassword);
    if (password == null) {
      return SYNTAX;
    }
    try {
      return authenticate(session, username, password, 0, password.length);
    } finally {
      Arrays.fill(password, (byte) 0);
    }
  }

  private Response plain(SMTPSession session, String encoded) {
    byte[] data = decode(encoded);
    if (data == null) {
      return SYNTAX;
    }
    try {
      int first = indexOf(data, 0);
      int second = first < 0 ? -1 : indexOf(data, first + 1);
      if (first < 0 || second < 0 || indexOf(data, second + 1) >= 0) {
        return SYNTAX;
      }
      String authzid = new String(data, 0, first, StandardCharsets.UTF_8);
      String authcid = new String(data, first + 1, second - first - 1, StandardCharsets.UTF_8);
      if (!authzid.isEmpty() && !authzid.equalsIgnoreCase(authcid)) {
        return failure(session);
      }
      return authenticate(session, authcid, data, second + 1, data.length);
    } finally {
      Arrays.fill(data, (byte) 0);
    }
  }

  private Response authenticate(
      SMTPSession session, String username, byte[] bytes, int from, int to) {
    CharBuffer password;
    try {
      password =
          StandardCharsets.UTF_8
              .newDecoder()
              .onMalformedInput(CodingErrorAction.REPORT)
              .decode(ByteBuffer.wrap(bytes, from, to - from));
    } catch (CharacterCodingException e) {
      return SYNTAX;
    }
    InetAddress source = session.getRemoteAddress().getAddress();
    try {
      MailboxLease lease =
          sessions.authenticateMailClient(username, password, source, Capability.SUBMIT);
      session.setAttachment(LEASE, lease, ProtocolSession.State.Connection);
      session.setUsername(Username.of(lease.principal().address().toString()));
      return OK;
    } catch (AuthenticationException e) {
      return switch (e.reason()) {
        case THROTTLED, UNAVAILABLE -> UNAVAILABLE;
        case INVALID, NOT_PERMITTED -> failure(session);
      };
    } finally {
      if (password.hasArray()) {
        Arrays.fill(password.array(), '\0');
      }
    }
  }

  private static Response failure(SMTPSession session) {
    int failures = session.getAttachment(FAILURES, ProtocolSession.State.Connection).orElse(0) + 1;
    session.setAttachment(FAILURES, failures, ProtocolSession.State.Connection);
    return failures >= MAX_FAILURES_PER_CONNECTION ? TOO_MANY : FAILED;
  }

  private static byte @Nullable [] decode(String value) {
    try {
      return Base64.getDecoder().decode(value);
    } catch (IllegalArgumentException e) {
      return null;
    }
  }

  private static int indexOf(byte[] data, int from) {
    for (int i = from; i < data.length; i++) {
      if (data[i] == 0) {
        return i;
      }
    }
    return -1;
  }
}
