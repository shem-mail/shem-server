package org.shem.extract;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.StringWriter;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.apache.tika.config.EmbeddedLimits;
import org.apache.tika.exception.EmbeddedLimitReachedException;
import org.apache.tika.exception.EncryptedDocumentException;
import org.apache.tika.exception.TikaMemoryLimitException;
import org.apache.tika.exception.WriteLimitReachedException;
import org.apache.tika.io.TikaInputStream;
import org.apache.tika.metadata.Metadata;
import org.apache.tika.metadata.TikaCoreProperties;
import org.apache.tika.mime.MediaType;
import org.apache.tika.parser.AutoDetectParser;
import org.apache.tika.parser.ParseContext;
import org.apache.tika.parser.Parser;
import org.apache.tika.sax.BodyContentHandler;
import org.apache.tika.sax.WriteOutContentHandler;

/**
 * The worker process (ADR 0019): answers the isolation probe, then extracts text from one request
 * at a time with Tika until stdin closes. It writes nothing but protocol frames to stdout and
 * nothing to disk except what parsers spill into {@code java.io.tmpdir} (the parent's scratch
 * directory). It never sees keys, tokens, or mailbox paths.
 */
public final class ExtractionWorker {
  static final int MAX_EMBEDDED_DEPTH = 4;
  static final int MAX_EMBEDDED_COUNT = 100;

  private ExtractionWorker() {}

  public static void main(String[] args) throws IOException {
    DataInputStream in = new DataInputStream(new BufferedInputStream(System.in));
    // Keep the real stdout for protocol frames only; libraries that print go to stderr, which the
    // parent discards.
    DataOutputStream out =
        new DataOutputStream(
            new BufferedOutputStream(new java.io.FileOutputStream(java.io.FileDescriptor.out)));
    System.setOut(System.err);
    handshake(in, out);
    AutoDetectParser parser = new AutoDetectParser();
    while (true) {
      byte type;
      try {
        type = in.readByte();
      } catch (EOFException e) {
        return;
      }
      if (type != Protocol.REQUEST) {
        throw new IOException("unexpected frame");
      }
      String contentType = Protocol.readString(in);
      String extension = Protocol.readString(in);
      int maxChars = in.readInt();
      byte[] content = Protocol.readBytes(in, Integer.MAX_VALUE - 8);
      Result result = extract(parser, content, contentType, extension, maxChars);
      out.writeByte(result.status);
      out.writeBoolean(result.truncated);
      byte[] text = result.text.getBytes(StandardCharsets.UTF_8);
      out.writeInt(text.length);
      out.write(text);
      out.flush();
    }
  }

  private record Result(byte status, boolean truncated, String text) {}

  private static Result extract(
      AutoDetectParser parser, byte[] content, String contentType, String extension, int maxChars) {
    Metadata metadata = new Metadata();
    if (!contentType.isEmpty()) {
      metadata.set(TikaCoreProperties.CONTENT_TYPE_HINT, contentType);
    }
    if (!extension.isEmpty()) {
      metadata.set(TikaCoreProperties.RESOURCE_NAME_KEY, "attachment." + extension);
    }
    StringWriter text = new StringWriter();
    WriteOutContentHandler limit = new WriteOutContentHandler(text, maxChars);
    ParseContext context = new ParseContext();
    context.set(Parser.class, parser);
    context.set(
        EmbeddedLimits.class,
        new EmbeddedLimits(MAX_EMBEDDED_DEPTH, true, MAX_EMBEDDED_COUNT, true));
    try (TikaInputStream stream = TikaInputStream.get(content, metadata)) {
      MediaType detected = parser.getDetector().detect(stream, metadata, context);
      if (!supported(parser, detected, context)) {
        return new Result(Protocol.UNSUPPORTED, false, "");
      }
      parser.parse(stream, new BodyContentHandler(limit), metadata, context);
      return new Result(Protocol.TEXT, false, text.toString());
    } catch (EncryptedDocumentException e) {
      return new Result(Protocol.ENCRYPTED, false, "");
    } catch (EmbeddedLimitReachedException | TikaMemoryLimitException e) {
      return new Result(Protocol.LIMIT, false, "");
    } catch (Exception e) {
      if (WriteLimitReachedException.isWriteLimitReached(e)) {
        return new Result(Protocol.TEXT, true, text.toString());
      }
      if (isZipBomb(e)) {
        return new Result(Protocol.LIMIT, false, "");
      }
      if (hasCause(e, EncryptedDocumentException.class)) {
        return new Result(Protocol.ENCRYPTED, false, "");
      }
      return new Result(Protocol.FAILED, false, "");
    } catch (OutOfMemoryError e) {
      return new Result(Protocol.LIMIT, false, "");
    }
  }

  private static boolean supported(AutoDetectParser parser, MediaType type, ParseContext context) {
    var registry = parser.getMediaTypeRegistry();
    for (MediaType candidate = type;
        candidate != null;
        candidate = registry.getSupertype(candidate)) {
      if (candidate.equals(MediaType.OCTET_STREAM)) {
        return false;
      }
      if (parser.getSupportedTypes(context).contains(candidate)) {
        return true;
      }
    }
    return false;
  }

  private static boolean isZipBomb(Throwable e) {
    for (Throwable t = e; t != null; t = t.getCause()) {
      String name = t.getClass().getName();
      String message = String.valueOf(t.getMessage()).toLowerCase(java.util.Locale.ROOT);
      if (name.endsWith("ZipBombException")
          || message.contains("zip bomb")
          || message.contains("compression ratio")) {
        return true;
      }
    }
    return false;
  }

  private static boolean hasCause(Throwable e, Class<? extends Throwable> type) {
    for (Throwable t = e; t != null; t = t.getCause()) {
      if (type.isInstance(t)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Reports what this process can reach: the parent's loopback probe port, the canary file in the
   * data directory, and whether its temp directory is the scratch directory on tmpfs.
   */
  private static void handshake(DataInputStream in, DataOutputStream out) throws IOException {
    Protocol.expectMagic(in);
    int probePort = in.readInt();
    String canary = Protocol.readString(in);
    String scratch = Protocol.readString(in);
    boolean network;
    try (Socket socket = new Socket()) {
      socket.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(), probePort), 2000);
      network = true;
    } catch (IOException e) {
      network = false;
    }
    boolean canaryReadable;
    try {
      Files.readAllBytes(Path.of(canary));
      canaryReadable = true;
    } catch (IOException | SecurityException e) {
      canaryReadable = false;
    }
    String tmpdir = System.getProperty("java.io.tmpdir", "");
    out.writeInt(Protocol.MAGIC);
    out.writeBoolean(network);
    out.writeBoolean(canaryReadable);
    Protocol.writeString(out, tmpdir);
    out.writeBoolean(
        Path.of(tmpdir).toAbsolutePath().normalize().equals(Path.of(scratch)) && onTmpfs(tmpdir));
    out.flush();
  }

  /** Linux: the longest mount point containing {@code dir} has type tmpfs or ramfs. */
  static boolean onTmpfs(String dir) {
    Path target = Path.of(dir).toAbsolutePath().normalize();
    String bestType = null;
    int bestLength = -1;
    try {
      List<String> mounts = Files.readAllLines(Path.of("/proc/self/mounts"));
      for (String line : mounts) {
        String[] fields = line.split(" ", -1);
        if (fields.length < 3) {
          continue;
        }
        Path mountPoint = Path.of(fields[1].replace("\\040", " "));
        if (target.startsWith(mountPoint) && mountPoint.toString().length() > bestLength) {
          bestLength = mountPoint.toString().length();
          bestType = fields[2];
        }
      }
    } catch (IOException | RuntimeException e) {
      return false;
    }
    return "tmpfs".equals(bestType) || "ramfs".equals(bestType);
  }
}
