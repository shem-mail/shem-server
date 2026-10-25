package org.shem.tls;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.time.Duration;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Polls the certificate and key files and reloads the context when either changes (for example
 * after an ACME renewal or an operator replacing files). Polling avoids platform-specific file
 * watching and handles atomic renames.
 */
public final class CertificateWatcher implements AutoCloseable {
  private final ReloadableTlsContext context;
  private final Path chainFile;
  private final Path keyFile;
  private final ScheduledExecutorService scheduler;
  private final java.util.concurrent.ScheduledFuture<?> task;
  private FileTime lastChain;
  private FileTime lastKey;

  public CertificateWatcher(
      ReloadableTlsContext context, Path chainFile, Path keyFile, Duration interval) {
    this.context = context;
    this.chainFile = chainFile;
    this.keyFile = keyFile;
    this.lastChain = modified(chainFile);
    this.lastKey = modified(keyFile);
    this.scheduler =
        Executors.newSingleThreadScheduledExecutor(
            Thread.ofPlatform().daemon().name("cert-watcher").factory());
    this.task =
        scheduler.scheduleWithFixedDelay(
            this::checkSafely, interval.toMillis(), interval.toMillis(), TimeUnit.MILLISECONDS);
  }

  /** Checks once; returns true if a new certificate was installed. */
  synchronized boolean check() {
    FileTime chain = modified(chainFile);
    FileTime key = modified(keyFile);
    if (chain.equals(lastChain) && key.equals(lastKey)) {
      return false;
    }
    lastChain = chain;
    lastKey = key;
    return context.reload();
  }

  private void checkSafely() {
    try {
      check();
    } catch (RuntimeException e) {
      // Keep polling: a transient failure must not stop future renewals from being picked up.
      System.getLogger(CertificateWatcher.class.getName())
          .log(
              System.Logger.Level.WARNING,
              "certificate check failed: " + e.getClass().getSimpleName());
    }
  }

  private static FileTime modified(Path file) {
    try {
      return Files.getLastModifiedTime(file);
    } catch (IOException e) {
      return FileTime.fromMillis(0);
    }
  }

  @Override
  public void close() {
    task.cancel(false);
    scheduler.shutdownNow();
  }
}
