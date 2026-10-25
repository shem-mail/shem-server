package org.shem.store;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.function.IntFunction;
import org.shem.common.DurableFiles;
import org.shem.common.FaultInjector;
import org.shem.common.FormatException;
import org.shem.common.IdGenerator;
import org.shem.common.OpaqueId;
import org.shem.common.RecordReader;
import org.shem.common.RecordWriter;
import org.shem.crypto.AssociatedData;
import org.shem.crypto.CryptoException;
import org.shem.crypto.CryptoProfile;
import org.shem.crypto.MailboxPrivateKey;
import org.shem.crypto.MailboxPublicKey;
import org.shem.crypto.PublicKeyEnvelopes;
import org.shem.crypto.Purpose;
import org.shem.crypto.Secret;
import org.shem.crypto.SymmetricKey;

/**
 * Encrypted delivery receipts: the locked-mailbox delivery journal.
 *
 * <p>Each receipt is one immutable file {@code r-<millis>-<receiptId>} in the mailbox's receipt
 * directory. The name reveals only arrival order and time, which file metadata exposes anyway.
 * Contents: {@code "SHRC", u8 format, u8 profile, id receipt, bytes hpkeEnvelope(receiptKey), bytes
 * aesGcm(receiptKey, body)}; both layers bind mailbox and receipt id.
 */
public final class ReceiptStore {
  public static final String FAULT_BEFORE_PUBLISH = "receipt.before-publish";
  private static final byte[] MAGIC = {'S', 'H', 'R', 'C'};
  private static final int FORMAT = 1;
  private static final int MAX_FILE = 256 * 1024;
  private static final int MAX_TEXT = 4096;

  private final MailboxPaths paths;
  private final IdGenerator ids;
  private final SecureRandom random;
  private final Clock clock;
  private final FaultInjector faults;

  public ReceiptStore(
      MailboxPaths paths, IdGenerator ids, SecureRandom random, Clock clock, FaultInjector faults) {
    this.paths = paths;
    this.ids = ids;
    this.random = random;
    this.clock = clock;
    this.faults = faults;
  }

  /** A receipt file awaiting import. */
  public record PendingReceipt(OpaqueId receiptId, long sequence, Path file) {}

  /** Durably writes a receipt sealed to {@code recipientKey}. */
  public PendingReceipt write(OpaqueId mailboxId, MailboxPublicKey recipientKey, Receipt receipt)
      throws StorageException {
    OpaqueId receiptId = ids.next();
    long sequence = clock.millis();
    AssociatedData context = context(mailboxId, receiptId);
    byte[] body = encodeBody(receipt);
    try (SymmetricKey receiptKey = SymmetricKey.generate(random)) {
      byte[] envelope = PublicKeyEnvelopes.sealKey(recipientKey, context, receiptKey);
      byte[] sealedBody = receiptKey.seal(body, context);
      byte[] file =
          new RecordWriter()
              .raw(MAGIC)
              .u8(FORMAT)
              .u8(CryptoProfile.PROFILE_VERSION)
              .id(receiptId)
              .bytes(envelope)
              .bytes(sealedBody)
              .toByteArray();
      Path directory = DurableFiles.createPrivateDirectories(paths.receipts(mailboxId));
      Path target = directory.resolve(fileName(sequence, receiptId));
      faults.at(FAULT_BEFORE_PUBLISH);
      DurableFiles.writeNew(target, file);
      return new PendingReceipt(receiptId, sequence, target);
    } catch (CryptoException e) {
      throw new StorageException(StorageException.Kind.UNAVAILABLE, "receipt sealing failed", e);
    } catch (IOException e) {
      throw new StorageException(StorageException.Kind.UNAVAILABLE, "receipt write failed", e);
    } finally {
      java.util.Arrays.fill(body, (byte) 0);
    }
  }

  /** Pending receipts in stable import order. */
  public List<PendingReceipt> list(OpaqueId mailboxId) throws StorageException {
    Path directory = paths.receipts(mailboxId);
    List<PendingReceipt> result = new ArrayList<>();
    if (!Files.isDirectory(directory)) {
      return result;
    }
    try (var files = Files.list(directory)) {
      for (Path file : (Iterable<Path>) files::iterator) {
        parseName(file).ifPresent(result::add);
      }
    } catch (IOException e) {
      throw new StorageException(StorageException.Kind.UNAVAILABLE, "receipt listing failed", e);
    }
    result.sort(
        java.util.Comparator.comparingLong(PendingReceipt::sequence)
            .thenComparing(PendingReceipt::receiptId));
    return result;
  }

  /** Key version a pending receipt was sealed to (readable without decrypting). */
  public int keyVersion(PendingReceipt pending) throws StorageException {
    try {
      RecordReader reader = header(Files.readAllBytes(pending.file()), pending.receiptId());
      return PublicKeyEnvelopes.keyVersionOf(reader.bytes(MAX_FILE));
    } catch (IOException e) {
      throw new StorageException(StorageException.Kind.UNAVAILABLE, "receipt read failed", e);
    } catch (FormatException | CryptoException e) {
      throw new StorageException(StorageException.Kind.CORRUPT, "malformed receipt", e);
    }
  }

  /** Decrypts a receipt using the private key for the version it was sealed to. */
  public Receipt open(
      OpaqueId mailboxId,
      PendingReceipt pending,
      IntFunction<Optional<MailboxPrivateKey>> privateKeys)
      throws StorageException {
    try {
      byte[] data = Files.readAllBytes(pending.file());
      if (data.length > MAX_FILE) {
        throw new StorageException(StorageException.Kind.CORRUPT, "receipt too large");
      }
      RecordReader reader = header(data, pending.receiptId());
      byte[] envelope = reader.bytes(MAX_FILE);
      byte[] sealedBody = reader.bytes(MAX_FILE);
      reader.expectEnd();
      int keyVersion = PublicKeyEnvelopes.keyVersionOf(envelope);
      MailboxPrivateKey key =
          privateKeys
              .apply(keyVersion)
              .orElseThrow(
                  () ->
                      new StorageException(
                          StorageException.Kind.CORRUPT, "receipt sealed to an unavailable key"));
      AssociatedData context = context(mailboxId, pending.receiptId());
      try (SymmetricKey receiptKey = PublicKeyEnvelopes.openKey(key, context, envelope);
          Secret body = receiptKey.open(sealedBody, context)) {
        return decodeBody(body.exposeCopy());
      }
    } catch (IOException e) {
      throw new StorageException(StorageException.Kind.UNAVAILABLE, "receipt read failed", e);
    } catch (FormatException | CryptoException e) {
      throw new StorageException(StorageException.Kind.CORRUPT, "receipt failed verification", e);
    }
  }

  /** Removes an imported receipt. Only call after the import is durably committed. */
  public void retire(PendingReceipt pending) throws StorageException {
    try {
      DurableFiles.deleteDurably(pending.file());
    } catch (IOException e) {
      throw new StorageException(StorageException.Kind.UNAVAILABLE, "receipt retire failed", e);
    }
  }

  private static RecordReader header(byte[] data, OpaqueId expectedId) throws FormatException {
    RecordReader reader = new RecordReader(data);
    if (!java.util.Arrays.equals(reader.raw(4), MAGIC)) {
      throw new FormatException("not a receipt");
    }
    if (reader.u8() != FORMAT || reader.u8() != CryptoProfile.PROFILE_VERSION) {
      throw new FormatException("unsupported receipt version");
    }
    if (!reader.id().equals(expectedId)) {
      throw new FormatException("receipt id mismatch");
    }
    return reader;
  }

  private static byte[] encodeBody(Receipt r) {
    RecordWriter out =
        new RecordWriter()
            .id(r.deliveryId())
            .id(r.blobId())
            .i64(r.plaintextBytes())
            .i64(r.internalDateMillis())
            .u16(r.systemFlags());
    try (Secret key = r.contentKey().exportSecret()) {
      out.bytes(key.exposeCopy());
    }
    out.u16(r.keywords().size());
    r.keywords().forEach(out::string);
    switch (r.target()) {
      case DeliveryTarget.Role role -> out.u8(1).u8(role.role().code());
      case DeliveryTarget.Folder folder -> out.u8(2).id(folder.folderId());
    }
    out.string(r.envelopeSender()).string(r.recipient());
    out.u16(r.policyTags().size());
    r.policyTags().forEach(out::string);
    return out.toByteArrayAndWipe();
  }

  private static Receipt decodeBody(byte[] body) throws FormatException {
    try {
      RecordReader in = new RecordReader(body);
      OpaqueId deliveryId = in.id();
      OpaqueId blobId = in.id();
      long size = in.i64();
      long internalDate = in.i64();
      int flags = in.u16();
      SymmetricKey contentKey = SymmetricKey.of(Secret.wrap(in.bytes(64)));
      try {
        List<String> keywords = new ArrayList<>();
        for (int i = 0, n = in.u16(); i < n; i++) {
          keywords.add(in.string(MAX_TEXT));
        }
        DeliveryTarget target =
            switch (in.u8()) {
              case 1 -> new DeliveryTarget.Role(SpecialUse.fromCode(in.u8()));
              case 2 -> new DeliveryTarget.Folder(in.id());
              default -> throw new FormatException("unknown delivery target");
            };
        String sender = in.string(MAX_TEXT);
        String recipient = in.string(MAX_TEXT);
        List<String> tags = new ArrayList<>();
        for (int i = 0, n = in.u16(); i < n; i++) {
          tags.add(in.string(MAX_TEXT));
        }
        in.expectEnd();
        return new Receipt(
            deliveryId,
            blobId,
            contentKey,
            size,
            internalDate,
            flags,
            keywords,
            target,
            sender,
            recipient,
            tags);
      } catch (FormatException | RuntimeException e) {
        contentKey.close();
        throw e;
      }
    } catch (IllegalArgumentException e) {
      throw new FormatException("invalid receipt body", e);
    } finally {
      java.util.Arrays.fill(body, (byte) 0);
    }
  }

  private static String fileName(long sequence, OpaqueId receiptId) {
    return "r-" + HexFormat.of().toHexDigits(sequence) + "-" + receiptId.value();
  }

  private static Optional<PendingReceipt> parseName(Path file) {
    String name = String.valueOf(file.getFileName());
    if (!name.startsWith("r-") || name.length() != 2 + 16 + 1 + 32 || name.charAt(18) != '-') {
      return Optional.empty();
    }
    OpaqueId id = OpaqueId.parseOrNull(name.substring(19));
    if (id == null) {
      return Optional.empty();
    }
    try {
      long sequence = HexFormat.fromHexDigitsToLong(name.substring(2, 18));
      return Optional.of(new PendingReceipt(id, sequence, file));
    } catch (NumberFormatException e) {
      return Optional.empty();
    }
  }

  private static AssociatedData context(OpaqueId mailboxId, OpaqueId receiptId) {
    return AssociatedData.builder(Purpose.DELIVERY_RECEIPT, FORMAT)
        .id("mailbox", mailboxId)
        .id("receipt", receiptId)
        .build();
  }
}
