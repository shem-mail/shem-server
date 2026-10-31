package org.shem.smtp;

import java.io.IOException;
import org.apache.james.protocols.api.handler.DisconnectHandler;
import org.apache.james.protocols.smtp.SMTPSession;

/** Wipes envelopes left open by a disconnect or an aborted DATA. */
final class EnvelopeCleanup implements DisconnectHandler<SMTPSession> {
  private static final System.Logger LOG = System.getLogger(EnvelopeCleanup.class.getName());

  @Override
  public void onDisconnect(SMTPSession session) {
    try {
      Transactions.discardAll(session);
    } catch (IOException e) {
      // Keys are wiped before deletion; leftover ciphertext is removed by the start-up sweep.
      LOG.log(
          System.Logger.Level.WARNING, "spool cleanup failed: {0}", e.getClass().getSimpleName());
    }
  }
}
