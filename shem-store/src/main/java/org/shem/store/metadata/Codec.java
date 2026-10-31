package org.shem.store.metadata;

import java.util.ArrayList;
import java.util.List;
import org.shem.common.FormatException;
import org.shem.common.ImmutableBytes;
import org.shem.common.OpaqueId;
import org.shem.common.RecordReader;
import org.shem.common.RecordWriter;
import org.shem.store.SpecialUse;

/** Binary encoding of metadata values and operations (journal/snapshot format 1). */
final class Codec {
  static final int MAX_TEXT = 4096;
  static final int MAX_BYTES = 1 << 20;

  private Codec() {}

  static void folder(RecordWriter out, Folder f) {
    out.id(f.folderId())
        .string(f.name())
        .u32(f.uidValidity())
        .i64(f.uidNext())
        .u8(f.specialUse().code());
  }

  static Folder folder(RecordReader in) throws FormatException {
    OpaqueId id = in.id();
    String name = in.string(Folder.MAX_NAME_BYTES);
    long uidValidity = in.u32();
    long uidNext = in.i64();
    int use = in.u8();
    try {
      return new Folder(id, name, uidValidity, uidNext, SpecialUse.fromCode(use));
    } catch (IllegalArgumentException e) {
      throw new FormatException("invalid folder", e);
    }
  }

  static void flags(RecordWriter out, Flags flags) {
    out.u8(flags.system()).u16(flags.keywords().size());
    flags.keywords().forEach(out::string);
  }

  static Flags flags(RecordReader in) throws FormatException {
    int system = in.u8();
    int count = in.u16();
    if (count > Flags.MAX_KEYWORDS) {
      throw new FormatException("too many keywords");
    }
    List<String> keywords = new ArrayList<>(count);
    for (int i = 0; i < count; i++) {
      keywords.add(in.string(MAX_TEXT));
    }
    try {
      return new Flags(system, keywords);
    } catch (IllegalArgumentException e) {
      throw new FormatException("invalid flags", e);
    }
  }

  static void key(RecordWriter out, MessageKey key) {
    out.id(key.folderId()).u32(key.uid());
  }

  static MessageKey key(RecordReader in) throws FormatException {
    OpaqueId folder = in.id();
    long uid = in.u32();
    if (uid == 0) {
      throw new FormatException("zero uid");
    }
    return new MessageKey(folder, uid);
  }

  static void record(RecordWriter out, MessageRecord r) {
    out.id(r.blobId())
        .bytes(r.wrappedContentKey().toByteArray())
        .i64(r.size())
        .i64(r.internalDateMillis())
        .i64(r.modSeq());
    flags(out, r.flags());
    out.bytes(r.summary().toByteArray());
  }

  static MessageRecord record(RecordReader in) throws FormatException {
    OpaqueId blob = in.id();
    ImmutableBytes wrapped = ImmutableBytes.copyOf(in.bytes(256));
    long size = in.i64();
    long date = in.i64();
    long modSeq = in.i64();
    Flags flags = flags(in);
    ImmutableBytes summary = ImmutableBytes.copyOf(in.bytes(MessageRecord.MAX_SUMMARY_BYTES));
    try {
      return new MessageRecord(blob, wrapped, size, date, modSeq, flags, summary);
    } catch (IllegalArgumentException e) {
      throw new FormatException("invalid message record", e);
    }
  }

  static void op(RecordWriter out, Op op) {
    switch (op) {
      case Op.CreateFolder c -> {
        out.u8(1);
        folder(out, c.folder());
      }
      case Op.RenameFolder r -> out.u8(2).id(r.folderId()).string(r.name());
      case Op.DeleteFolder d -> out.u8(3).id(d.folderId());
      case Op.Subscribe s -> out.u8(4).string(s.name()).bool(s.subscribed());
      case Op.PutMessage p -> {
        out.u8(5);
        key(out, p.key());
        record(out, p.record());
      }
      case Op.SetFlags f -> {
        out.u8(6);
        key(out, f.key());
        flags(out, f.flags());
        out.i64(f.modSeq());
      }
      case Op.RemoveMessage r -> {
        out.u8(7);
        key(out, r.key());
        out.i64(r.modSeq());
      }
      case Op.ReceiptImported r -> out.u8(8).id(r.receiptId()).i64(r.importedAtMillis());
      case Op.ForgetReceipt f -> out.u8(9).id(f.receiptId());
      case Op.SetProperty p -> out.u8(10).string(p.key()).bytes(p.value().toByteArray());
    }
  }

  static Op op(RecordReader in) throws FormatException {
    int type = in.u8();
    return switch (type) {
      case 1 -> new Op.CreateFolder(folder(in));
      case 2 -> new Op.RenameFolder(in.id(), in.string(Folder.MAX_NAME_BYTES));
      case 3 -> new Op.DeleteFolder(in.id());
      case 4 -> new Op.Subscribe(in.string(Folder.MAX_NAME_BYTES), in.bool());
      case 5 -> new Op.PutMessage(key(in), record(in));
      case 6 -> new Op.SetFlags(key(in), flags(in), in.i64());
      case 7 -> new Op.RemoveMessage(key(in), in.i64());
      case 8 -> new Op.ReceiptImported(in.id(), in.i64());
      case 9 -> new Op.ForgetReceipt(in.id());
      case 10 ->
          new Op.SetProperty(in.string(MAX_TEXT), ImmutableBytes.copyOf(in.bytes(MAX_BYTES)));
      default -> throw new FormatException("unknown metadata operation");
    };
  }
}
