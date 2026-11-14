package net.shem.identity;

import net.shem.common.OpaqueId;
import net.shem.crypto.MailboxPublicKey;

/** What locked delivery needs to know about a local recipient: where and with which key. */
public record RecipientRoute(OpaqueId mailboxId, MailboxPublicKey publicKey, long quotaBytes) {}
