package org.shem.mailbox;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.util.Comparator;
import org.shem.common.IdGenerator;
import org.shem.common.OpaqueId;
import org.shem.crypto.Argon2Parameters;
import org.shem.crypto.Argon2idKdf;
import org.shem.crypto.CryptoException;
import org.shem.crypto.KdfAdmission;
import org.shem.crypto.KeySlot;
import org.shem.crypto.Keyring;
import org.shem.crypto.MailboxPrivateKey;
import org.shem.crypto.Secret;
import org.shem.crypto.SlotDescriptor;
import org.shem.crypto.SlotKind;
import org.shem.crypto.SymmetricKey;
import org.shem.identity.Account;
import org.shem.identity.EmailAddress;
import org.shem.identity.IdentityException;
import org.shem.identity.IdentityService;
import org.shem.store.MailboxPaths;
import org.shem.store.SpecialUse;
import org.shem.store.StorageException;
import org.shem.store.metadata.MetadataStore;

/**
 * Creates accounts: a fresh mailbox id, bootstrap keypair, data root, master key, a short-lived
 * bootstrap slot, an encrypted metadata store with default folders, and finally the routing entry
 * (the commit point). The bootstrap password is returned exactly once and is never stored.
 */
public final class MailboxProvisioning {
  private final IdentityService identity;
  private final MailboxPaths paths;
  private final KeyFiles keyFiles;
  private final Argon2idKdf kdf;
  private final Argon2Parameters slotParameters;
  private final MetadataStore.Environment metadataEnvironment;
  private final IdGenerator ids;
  private final SecureRandom random;
  private final Clock clock;

  public MailboxProvisioning(
      IdentityService identity,
      MailboxPaths paths,
      Argon2idKdf kdf,
      Argon2Parameters slotParameters,
      MetadataStore.Environment metadataEnvironment,
      IdGenerator ids,
      SecureRandom random,
      Clock clock) {
    this.identity = identity;
    this.paths = paths;
    this.keyFiles = new KeyFiles(paths, kdf.limits());
    this.kdf = kdf;
    this.slotParameters = slotParameters;
    this.metadataEnvironment = metadataEnvironment;
    this.ids = ids;
    this.random = random;
    this.clock = clock;
  }

  /** The new account and its one-time bootstrap password (caller closes the secret). */
  public record Provisioned(Account account, Secret bootstrapPassword) {}

  public Provisioned provision(EmailAddress address, long quotaBytes, Duration bootstrapValidity)
      throws IdentityException,
          StorageException,
          CryptoException,
          KdfAdmission.Rejected,
          InterruptedException {
    OpaqueId mailboxId = ids.next();
    Secret bootstrap = Credentials.generate(random, "", 6);
    boolean success = false;
    try (SymmetricKey master = SymmetricKey.generate(random)) {
      OpaqueId slotId = ids.next();
      KeySlot slot =
          KeySlot.create(
              mailboxId,
              slotId,
              SlotKind.BOOTSTRAP,
              bootstrap,
              master,
              slotParameters,
              kdf,
              random);
      try (Keyring initial =
              Keyring.create(
                  mailboxId, MailboxPrivateKey.generate(1), SymmetricKey.generate(random), 1);
          Keyring keyring =
              initial.withSlotAdded(
                  new SlotDescriptor(slotId, SlotKind.BOOTSTRAP, "bootstrap", clock.instant()))) {
        keyFiles.writeSlot(slot, KeyFiles.NO_SELECTOR);
        keyFiles.writeKeyring(mailboxId, keyring.seal(master));
        try (MetadataStore metadata =
            MetadataStore.create(
                paths.metadata(mailboxId),
                mailboxId,
                keyring.currentDataRoot(),
                keyring.currentDataVersion(),
                metadataEnvironment)) {
          metadata.write(
              tx -> {
                for (SpecialUse role :
                    new SpecialUse[] {
                      SpecialUse.INBOX,
                      SpecialUse.SENT,
                      SpecialUse.DRAFTS,
                      SpecialUse.TRASH,
                      SpecialUse.JUNK
                    }) {
                  String name = defaultName(role);
                  tx.createFolder(name, role);
                  tx.setSubscribed(name, true);
                }
                return null;
              });
        }
        Account account =
            identity.createAccount(
                mailboxId, address, keyring.currentPublicKey(), quotaBytes, bootstrapValidity);
        success = true;
        return new Provisioned(account, bootstrap);
      }
    } finally {
      if (!success) {
        bootstrap.close();
        deleteQuietly(paths.mailbox(mailboxId));
      }
    }
  }

  static String defaultName(SpecialUse role) {
    return switch (role) {
      case INBOX -> "INBOX";
      case SENT -> "Sent";
      case DRAFTS -> "Drafts";
      case TRASH -> "Trash";
      case JUNK -> "Junk";
      case ARCHIVE -> "Archive";
      case NONE -> "Folder";
    };
  }

  private static void deleteQuietly(Path directory) {
    if (!Files.exists(directory)) {
      return;
    }
    try (var files = Files.walk(directory)) {
      for (Path p : (Iterable<Path>) files.sorted(Comparator.reverseOrder())::iterator) {
        Files.deleteIfExists(p);
      }
    } catch (IOException ignored) {
      // Leftover ciphertext of a failed provisioning has no routing entry and is unreachable.
    }
  }
}
