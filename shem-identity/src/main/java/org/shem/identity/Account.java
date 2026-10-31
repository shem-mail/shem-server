package org.shem.identity;

import java.time.Instant;
import org.jspecify.annotations.Nullable;
import org.shem.common.OpaqueId;
import org.shem.crypto.MailboxPublicKey;

/**
 * Account routing record. {@code mailboxId} is the only name used on disk for the mailbox;
 * recreating an address always allocates a new mailbox id (and therefore a new key and
 * UIDVALIDITY). {@code version} implements optimistic concurrency for administrative changes.
 */
public record Account(
    OpaqueId mailboxId,
    EmailAddress address,
    OpaqueId domainId,
    AccountState state,
    MailboxPublicKey publicKey,
    long quotaBytes,
    Instant createdAt,
    @Nullable Instant bootstrapExpiresAt,
    @Nullable Instant deletionRequestedAt,
    long version) {

  public Account withState(AccountState next, Instant now) {
    if (!state.canTransitionTo(next)) {
      throw new IllegalStateException("invalid account state transition");
    }
    Instant deletion =
        next == AccountState.DELETION_PENDING
            ? now
            : (next == AccountState.DELETED ? deletionRequestedAt : null);
    Instant bootstrap = next == AccountState.ACTIVE ? null : bootstrapExpiresAt;
    return new Account(
        mailboxId,
        address,
        domainId,
        next,
        publicKey,
        quotaBytes,
        createdAt,
        bootstrap,
        deletion,
        version + 1);
  }

  public Account withPublicKey(MailboxPublicKey key) {
    if (key.keyVersion() <= publicKey.keyVersion()) {
      throw new IllegalArgumentException("public key version must increase");
    }
    return new Account(
        mailboxId,
        address,
        domainId,
        state,
        key,
        quotaBytes,
        createdAt,
        bootstrapExpiresAt,
        deletionRequestedAt,
        version + 1);
  }

  public Account withQuota(long bytes) {
    if (bytes < 0) {
      throw new IllegalArgumentException("quota must not be negative");
    }
    return new Account(
        mailboxId,
        address,
        domainId,
        state,
        publicKey,
        bytes,
        createdAt,
        bootstrapExpiresAt,
        deletionRequestedAt,
        version + 1);
  }
}
