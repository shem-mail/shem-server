package org.shem.identity;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.jspecify.annotations.Nullable;
import org.shem.common.FormatException;
import org.shem.common.OpaqueId;
import org.shem.common.RecordReader;
import org.shem.common.RecordWriter;
import org.shem.crypto.MailboxPublicKey;

/**
 * Versioned binary encoding of the routing directory ({@code "SHID"}, format 1). The file is
 * public-by-design operational data; it is protected by filesystem permissions, not encryption.
 */
final class DirectoryCodec {
  private static final byte[] MAGIC = {'S', 'H', 'I', 'D'};
  private static final int FORMAT = 1;
  private static final int MAX_ENTRIES = 1_000_000;
  private static final int MAX_TEXT = 512;

  private DirectoryCodec() {}

  static byte[] encode(Directory directory) {
    RecordWriter out = new RecordWriter().raw(MAGIC).u8(FORMAT).i64(directory.generation());
    out.u32(directory.domainMap().size());
    for (Domain domain : directory.domainMap().values()) {
      out.id(domain.domainId())
          .string(domain.name())
          .i64(domain.createdAt().getEpochSecond())
          .string(domain.dkimSelector() == null ? "" : domain.dkimSelector())
          .i64(domain.version());
    }
    out.u32(directory.accountMap().size());
    for (Account account : directory.accountMap().values()) {
      out.id(account.mailboxId())
          .string(account.address().toString())
          .id(account.domainId())
          .u8(account.state().code())
          .u32(account.publicKey().keyVersion())
          .bytes(account.publicKey().toBytes())
          .i64(account.quotaBytes())
          .i64(account.createdAt().getEpochSecond());
      optionalInstant(out, account.bootstrapExpiresAt());
      optionalInstant(out, account.deletionRequestedAt());
      out.i64(account.version());
    }
    out.u32(directory.aliasMap().size());
    for (Alias alias : directory.aliasMap().values()) {
      out.id(alias.aliasId()).string(alias.address().toString()).u16(alias.targets().size());
      alias.targets().forEach(t -> out.string(t.toString()));
      out.u16(alias.senders().size());
      alias.senders().forEach(out::id);
      out.i64(alias.version());
    }
    return out.toByteArray();
  }

  static Directory decode(byte[] data) throws FormatException {
    RecordReader in = new RecordReader(data);
    if (!java.util.Arrays.equals(in.raw(4), MAGIC)) {
      throw new FormatException("not a directory file");
    }
    if (in.u8() != FORMAT) {
      throw new FormatException("unsupported directory format");
    }
    long generation = in.i64();
    try {
      Map<OpaqueId, Domain> domains = new HashMap<>();
      for (long i = 0, n = count(in); i < n; i++) {
        OpaqueId id = in.id();
        String name = in.string(MAX_TEXT);
        Instant created = Instant.ofEpochSecond(in.i64());
        String selector = in.string(MAX_TEXT);
        domains.put(
            id, new Domain(id, name, created, selector.isEmpty() ? null : selector, in.i64()));
      }
      Map<OpaqueId, Account> accounts = new HashMap<>();
      for (long i = 0, n = count(in); i < n; i++) {
        OpaqueId id = in.id();
        EmailAddress address = EmailAddress.parse(in.string(MAX_TEXT));
        OpaqueId domainId = in.id();
        AccountState state = AccountState.fromCode(in.u8());
        int keyVersion = (int) in.u32();
        MailboxPublicKey key = new MailboxPublicKey(keyVersion, in.bytes(64));
        long quota = in.i64();
        Instant created = Instant.ofEpochSecond(in.i64());
        Instant bootstrap = readOptionalInstant(in);
        Instant deletion = readOptionalInstant(in);
        accounts.put(
            id,
            new Account(
                id, address, domainId, state, key, quota, created, bootstrap, deletion, in.i64()));
      }
      Map<OpaqueId, Alias> aliases = new HashMap<>();
      for (long i = 0, n = count(in); i < n; i++) {
        OpaqueId id = in.id();
        EmailAddress address = EmailAddress.parse(in.string(MAX_TEXT));
        List<EmailAddress> targets = new ArrayList<>();
        for (int t = 0, tn = in.u16(); t < tn; t++) {
          targets.add(EmailAddress.parse(in.string(MAX_TEXT)));
        }
        List<OpaqueId> senders = new ArrayList<>();
        for (int s = 0, sn = in.u16(); s < sn; s++) {
          senders.add(in.id());
        }
        aliases.put(id, new Alias(id, address, targets, senders, in.i64()));
      }
      in.expectEnd();
      return new Directory(generation, domains, accounts, aliases);
    } catch (IllegalArgumentException e) {
      throw new FormatException("invalid directory entry", e);
    }
  }

  private static long count(RecordReader in) throws FormatException {
    long n = in.u32();
    if (n > MAX_ENTRIES) {
      throw new FormatException("directory too large");
    }
    return n;
  }

  private static void optionalInstant(RecordWriter out, @Nullable Instant instant) {
    out.bool(instant != null);
    if (instant != null) {
      out.i64(instant.getEpochSecond());
    }
  }

  private static @Nullable Instant readOptionalInstant(RecordReader in) throws FormatException {
    return in.bool() ? Instant.ofEpochSecond(in.i64()) : null;
  }
}
