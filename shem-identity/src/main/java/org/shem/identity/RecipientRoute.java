package org.shem.identity;

import org.shem.common.OpaqueId;
import org.shem.crypto.MailboxPublicKey;

/** What locked delivery needs to know about a local recipient: where and with which key. */
public record RecipientRoute(OpaqueId mailboxId, MailboxPublicKey publicKey, long quotaBytes) {}
