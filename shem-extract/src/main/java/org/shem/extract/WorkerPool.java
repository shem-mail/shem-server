package org.shem.extract;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.jspecify.annotations.Nullable;
import org.shem.common.DurableFiles;
import org.shem.search.AttachmentExtractor;

/**
 * Runs Tika in separate worker JVMs (ADR 0019). Each worker gets its own private scratch directory
 * as {@code java.io.tmpdir}, a fixed heap, no inherited environment, stderr discarded (no worker
 * logs), and is started through the configured sandbox prefix. Before first use the pool probes a
 * worker's isolation and, when isolation is required, refuses to run if the worker can reach the
 * network, read the data-directory canary, or write anywhere but tmpfs scratch. A request that
 * exceeds the wall-clock timeout kills its worker; workers are recycled after failures and after a
 * fixed number of requests, and their scratch is deleted every time.
 */
public final class WorkerPool implements AttachmentExtractor, AutoCloseable {
  private static final System.Logger LOG = System.getLogger(WorkerPool.class.getName());

  /** Thrown at startup when required isolation is missing. */
  public static final class IsolationException extends Exception {
    private static final long serialVersionUID = 1L;

    IsolationException(String message) {
      super(message);
    }
  }

  /** What a worker reported in its handshake. */
  public record Isolation(
      boolean networkReachable, boolean canaryReadable, String tmpdir, boolean tmpfsScratch) {
    public boolean isolated() {
      return !networkReachable && !canaryReadable && tmpfsScratch;
    }
  }

  private final ExtractionSettings settings;
  private final String mainClass;
  private final Semaphore permits;
  private final ArrayDeque<Worker> idle = new ArrayDeque<>();
  private final ExecutorService io =
      Executors.newThreadPerTaskExecutor(Thread.ofVirtual().name("shem-extract-io-", 0).factory());
  private volatile boolean closed;
  private volatile boolean started;
  private int nextWorker;

  public WorkerPool(ExtractionSettings settings) {
    this(settings, ExtractionWorker.class.getName());
  }

  WorkerPool(ExtractionSettings settings, String mainClass) {
    this.settings = settings;
    this.mainClass = mainClass;
    this.permits = new Semaphore(settings.workers(), true);
  }

  /**
   * Starts one worker, checks its isolation, and keeps it. Fails if isolation is required and
   * missing; otherwise logs what is missing.
   */
  public Isolation start() throws IOException, IsolationException {
    // Scratch left by a crashed run is removed before any worker starts. The root itself may be
    // the tmpfs mount point, so only its contents are deleted.
    DurableFiles.createPrivateDirectories(settings.scratch());
    try (var children = Files.list(settings.scratch())) {
      for (Path child : children.toList()) {
        deleteTree(child);
      }
    }
    Path canary = settings.canary();
    if (!Files.exists(canary)) {
      DurableFiles.createPrivateDirectories(java.util.Objects.requireNonNull(canary.getParent()));
      DurableFiles.writeAtomically(
          canary, "shem isolation canary\n".getBytes(StandardCharsets.US_ASCII));
    }
    Worker worker = launch();
    Isolation isolation = worker.isolation;
    if (!isolation.isolated()) {
      String missing =
          (isolation.networkReachable() ? " network reachable;" : "")
              + (isolation.canaryReadable() ? " data directory readable;" : "")
              + (isolation.tmpfsScratch() ? "" : " scratch is not a private tmpfs;");
      if (settings.requireIsolation()) {
        worker.destroy();
        throw new IsolationException("attachment extraction is not isolated:" + missing);
      }
      LOG.log(
          System.Logger.Level.WARNING, "attachment extraction runs WITHOUT isolation:" + missing);
    }
    synchronized (idle) {
      idle.push(worker);
    }
    started = true;
    return isolation;
  }

  @Override
  public Outcome extract(
      InputStream content, @Nullable String contentType, @Nullable String extension)
      throws UnavailableException, InterruptedException, IOException {
    byte[] bytes = readBounded(content, settings.maxInputBytes());
    if (bytes == null) {
      return new Outcome.LimitReached("input size");
    }
    if (closed || !started) {
      throw new UnavailableException("extraction not running");
    }
    permits.acquire();
    try {
      Worker worker = take();
      Future<Outcome> reply =
          io.submit(() -> worker.request(bytes, contentType, extension, settings.maxOutputChars()));
      try {
        Outcome outcome = reply.get(settings.timeout().toMillis(), TimeUnit.MILLISECONDS);
        giveBack(worker);
        return outcome;
      } catch (TimeoutException e) {
        reply.cancel(true);
        worker.destroy();
        return new Outcome.LimitReached("time");
      } catch (ExecutionException e) {
        worker.destroy();
        return new Outcome.Failed();
      } catch (InterruptedException e) {
        worker.destroy();
        throw e;
      }
    } finally {
      java.util.Arrays.fill(bytes, (byte) 0);
      permits.release();
    }
  }

  private Worker take() throws UnavailableException {
    synchronized (idle) {
      Worker worker = idle.poll();
      if (worker != null && worker.alive()) {
        return worker;
      }
      if (worker != null) {
        worker.destroy();
      }
    }
    try {
      return launch();
    } catch (IOException e) {
      throw new UnavailableException("worker failed to start", e);
    }
  }

  private void giveBack(Worker worker) {
    if (closed || worker.served >= settings.requestsPerWorker() || !worker.alive()) {
      worker.destroy();
      return;
    }
    synchronized (idle) {
      idle.push(worker);
    }
  }

  private Worker launch() throws IOException {
    int id;
    synchronized (this) {
      id = nextWorker++;
    }
    Path scratch = settings.scratch().toAbsolutePath().normalize().resolve("w" + id);
    deleteTree(scratch);
    DurableFiles.createPrivateDirectories(scratch);
    List<String> command = new ArrayList<>(settings.sandbox());
    command.add(Path.of(System.getProperty("java.home"), "bin", "java").toString());
    command.add("-Xmx" + settings.heapMiB() + "m");
    command.add("-XX:MaxMetaspaceSize=128m");
    command.add("-XX:MaxDirectMemorySize=64m");
    command.add("-XX:ActiveProcessorCount=1");
    command.add("-XX:+UseSerialGC");
    command.add("-XX:-HeapDumpOnOutOfMemoryError");
    command.add("-XX:-CreateCoredumpOnCrash");
    command.add("-XX:+DisableAttachMechanism");
    command.add("-XX:-UsePerfData");
    command.add("-Djava.io.tmpdir=" + scratch);
    command.add("-Djava.awt.headless=true");
    command.add("-cp");
    command.add(System.getProperty("java.class.path"));
    command.add(mainClass);
    ProcessBuilder builder = new ProcessBuilder(command);
    builder.environment().clear();
    builder.directory(scratch.toFile());
    builder.redirectError(ProcessBuilder.Redirect.DISCARD);
    Process process = builder.start();
    Worker worker = new Worker(process, scratch);
    try (ServerSocket probe = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
      Future<?> acceptor =
          io.submit(
              () -> {
                probe.accept().close();
                return null;
              });
      try {
        worker.isolation =
            worker.handshake(probe.getLocalPort(), settings.canary().toAbsolutePath(), scratch);
      } finally {
        acceptor.cancel(true);
      }
    } catch (IOException | RuntimeException e) {
      worker.destroy();
      throw e;
    }
    return worker;
  }

  /** Reads up to {@code limit} bytes; null if the stream is longer. */
  static byte @Nullable [] readBounded(InputStream in, int limit) throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream(Math.min(limit, 64 * 1024));
    byte[] buffer = new byte[16 * 1024];
    int total = 0;
    int n;
    while ((n = in.read(buffer)) > 0) {
      total += n;
      if (total > limit) {
        return null;
      }
      out.write(buffer, 0, n);
    }
    return out.toByteArray();
  }

  static void deleteTree(Path path) throws IOException {
    if (!Files.exists(path, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
      return;
    }
    try (var files = Files.walk(path)) {
      for (Path p : (Iterable<Path>) files.sorted(java.util.Comparator.reverseOrder())::iterator) {
        Files.deleteIfExists(p);
      }
    }
  }

  /** One worker process. */
  private final class Worker {
    final Process process;
    final Path scratch;
    final DataInputStream in;
    final DataOutputStream out;
    Isolation isolation = new Isolation(true, true, "", false);
    int served;

    Worker(Process process, Path scratch) {
      this.process = process;
      this.scratch = scratch;
      this.in = new DataInputStream(new BufferedInputStream(process.getInputStream()));
      this.out = new DataOutputStream(new BufferedOutputStream(process.getOutputStream()));
    }

    Isolation handshake(int probePort, Path canary, Path expectedScratch) throws IOException {
      Future<Isolation> reply =
          io.submit(
              () -> {
                out.writeInt(Protocol.MAGIC);
                out.writeInt(probePort);
                Protocol.writeString(out, canary.toString());
                Protocol.writeString(out, expectedScratch.toString());
                out.flush();
                Protocol.expectMagic(in);
                return new Isolation(
                    in.readBoolean(), in.readBoolean(), Protocol.readString(in), in.readBoolean());
              });
      try {
        return reply.get(60, TimeUnit.SECONDS);
      } catch (ExecutionException | TimeoutException e) {
        throw new IOException("worker handshake failed", e);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new IOException("interrupted during worker handshake", e);
      }
    }

    Outcome request(byte[] content, @Nullable String type, @Nullable String extension, int maxChars)
        throws IOException {
      served++;
      out.writeByte(Protocol.REQUEST);
      Protocol.writeString(out, type == null ? "" : truncate(type, 255));
      Protocol.writeString(out, extension == null ? "" : extension);
      out.writeInt(maxChars);
      out.writeInt(content.length);
      out.write(content);
      out.flush();
      byte status = in.readByte();
      boolean truncated = in.readBoolean();
      byte[] text = Protocol.readBytes(in, maxChars * 4 + 16);
      return switch (status) {
        case Protocol.TEXT -> new Outcome.Text(new String(text, StandardCharsets.UTF_8), truncated);
        case Protocol.UNSUPPORTED -> new Outcome.Unsupported();
        case Protocol.ENCRYPTED -> new Outcome.Encrypted();
        case Protocol.LIMIT -> new Outcome.LimitReached("parser");
        default -> new Outcome.Failed();
      };
    }

    boolean alive() {
      return process.isAlive();
    }

    void destroy() {
      process.destroyForcibly();
      try {
        process.waitFor(5, TimeUnit.SECONDS);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
      }
      try {
        deleteTree(scratch);
      } catch (IOException e) {
        LOG.log(System.Logger.Level.WARNING, "worker scratch cleanup failed");
      }
    }
  }

  private static String truncate(String value, int max) {
    return value.length() <= max ? value : value.substring(0, max);
  }

  @Override
  public void close() {
    closed = true;
    synchronized (idle) {
      for (Worker worker : idle) {
        worker.destroy();
      }
      idle.clear();
    }
    io.shutdownNow();
  }
}
