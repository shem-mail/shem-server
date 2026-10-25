package org.shem.smtp;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.james.protocols.api.ProtocolSession;
import org.apache.james.protocols.smtp.SMTPSession;
import org.shem.common.OpaqueId;
import org.shem.identity.RecipientRoute;

/** Per-session state Shem keeps in James session attachments. */
final class Transactions {
  /** Accepted recipients of the current transaction, deduplicated by mailbox. */
  static final class Recipients {
    private final Map<OpaqueId, Accepted> byMailbox = new LinkedHashMap<>();
    private int count;

    record Accepted(RecipientRoute route, String address) {}

    int count() {
      return count;
    }

    void add(String address, List<RecipientRoute> routes) {
      count++;
      for (RecipientRoute route : routes) {
        byMailbox.putIfAbsent(route.mailboxId(), new Accepted(route, address));
      }
    }

    List<Accepted> mailboxes() {
      return new ArrayList<>(byMailbox.values());
    }
  }

  static final ProtocolSession.AttachmentKey<Recipients> RECIPIENTS =
      ProtocolSession.AttachmentKey.of("shem.recipients", Recipients.class);
  static final ProtocolSession.AttachmentKey<Integer> UNKNOWN_RECIPIENTS =
      ProtocolSession.AttachmentKey.of("shem.unknownRecipients", Integer.class);
  static final ProtocolSession.AttachmentKey<Long> DATA_BYTES =
      ProtocolSession.AttachmentKey.of("shem.dataBytes", Long.class);
  static final ProtocolSession.AttachmentKey<Boolean> LINE_TOO_LONG =
      ProtocolSession.AttachmentKey.of("shem.lineTooLong", Boolean.class);
  static final ProtocolSession.AttachmentKey<Boolean> OVERSIZED =
      ProtocolSession.AttachmentKey.of("shem.oversized", Boolean.class);

  @SuppressWarnings("unchecked") // generic attachment key, as James does for RCPT_LIST
  static final ProtocolSession.AttachmentKey<Set<SpoolingEnvelope>> OPEN_ENVELOPES =
      ProtocolSession.AttachmentKey.of(
          "shem.openEnvelopes", (Class<Set<SpoolingEnvelope>>) (Class<?>) Set.class);

  private Transactions() {}

  static Recipients recipients(SMTPSession session) {
    return session
        .getAttachment(RECIPIENTS, ProtocolSession.State.Transaction)
        .orElseGet(
            () -> {
              Recipients created = new Recipients();
              session.setAttachment(RECIPIENTS, created, ProtocolSession.State.Transaction);
              return created;
            });
  }

  /** Tracks an envelope so a disconnect mid-DATA still wipes and deletes it. */
  static void track(SMTPSession session, SpoolingEnvelope envelope) {
    Set<SpoolingEnvelope> open =
        session
            .getAttachment(OPEN_ENVELOPES, ProtocolSession.State.Connection)
            .orElseGet(
                () -> {
                  Set<SpoolingEnvelope> created = ConcurrentHashMap.newKeySet();
                  session.setAttachment(OPEN_ENVELOPES, created, ProtocolSession.State.Connection);
                  return created;
                });
    open.add(envelope);
  }

  /** Wipes and forgets an envelope. */
  static void discard(SMTPSession session, SpoolingEnvelope envelope) throws IOException {
    session
        .getAttachment(OPEN_ENVELOPES, ProtocolSession.State.Connection)
        .ifPresent(open -> open.remove(envelope));
    envelope.close();
  }

  /** Wipes every envelope still open on this connection. */
  static void discardAll(SMTPSession session) throws IOException {
    Set<SpoolingEnvelope> open =
        session.getAttachment(OPEN_ENVELOPES, ProtocolSession.State.Connection).orElse(Set.of());
    IOException failure = null;
    for (SpoolingEnvelope envelope : List.copyOf(open)) {
      open.remove(envelope);
      try {
        envelope.close();
      } catch (IOException e) {
        if (failure == null) {
          failure = e;
        } else {
          failure.addSuppressed(e);
        }
      }
    }
    if (failure != null) {
      throw failure;
    }
  }
}
