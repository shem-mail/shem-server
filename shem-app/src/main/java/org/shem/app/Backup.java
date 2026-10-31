package org.shem.app;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.TreeMap;
import org.shem.common.DurableFiles;

/**
 * Offline backup, verification, and restore of a data directory (ADR 0020). Backups are taken under
 * the data-directory lock, so no writer is running and every committed object is on disk: the copy
 * is consistent by construction, and locked mailboxes are backed up as ciphertext without being
 * decrypted.
 *
 * <p>A backup directory holds the copied files plus {@code MANIFEST}, written last: format version,
 * scope flags, and one {@code sha256 size path} line per file, closed by a hash over the manifest
 * itself. Derived data (search and attachment indexes) and transient data (inbound spool, lock,
 * temp files, extraction canary) are never copied; indexes rebuild at the next unlock. The
 * plaintext outbound queue is excluded unless asked for, and server secrets (DKIM, ACME, admin
 * credentials) can be excluded so they are backed up separately under stricter protection.
 */
final class Backup {
  static final String MANIFEST = "MANIFEST";
  static final int FORMAT = 1;
  static final Set<String> SECRETS = Set.of("dkim", "acme", "admin");
  private static final Set<String> DERIVED = Set.of("searchindex", "attachmentindex");

  private Backup() {}

  /** What to include beyond mailbox and routing data. */
  record Scope(boolean includeQueue, boolean includeSecrets) {}

  /** One file in a backup. */
  record Entry(String path, long size, String sha256) {}

  /** Thrown when a backup is incomplete, altered, or of an unknown format. */
  static final class InvalidBackupException extends Exception {
    private static final long serialVersionUID = 1L;

    InvalidBackupException(String message) {
      super(message);
    }
  }

  /** Copies {@code data} into the new directory {@code target}. The caller holds the lock. */
  static List<Entry> create(Path data, Path target, Scope scope, Instant now) throws IOException {
    if (Files.exists(target)) {
      throw new IOException("backup target already exists");
    }
    DurableFiles.createPrivateDirectories(target);
    List<Entry> entries = new ArrayList<>();
    for (Path file : files(data, scope)) {
      String relative = data.relativize(file).toString();
      Path destination = target.resolve(relative);
      DurableFiles.createPrivateDirectories(
          java.util.Objects.requireNonNull(destination.getParent()));
      entries.add(new Entry(relative, Files.size(file), copy(file, destination)));
    }
    syncTree(target);
    String body =
        "shem-backup "
            + FORMAT
            + "\ncreated "
            + now
            + "\nqueue "
            + scope.includeQueue()
            + "\nsecrets "
            + scope.includeSecrets()
            + "\n"
            + lines(entries);
    DurableFiles.writeAtomically(
        target.resolve(MANIFEST),
        (body + "end " + sha256(body.getBytes(StandardCharsets.UTF_8)) + "\n")
            .getBytes(StandardCharsets.UTF_8));
    return entries;
  }

  /** Checks the manifest and every listed file; extra files are rejected too. */
  static List<Entry> verify(Path backup) throws IOException, InvalidBackupException {
    Path manifest = backup.resolve(MANIFEST);
    if (!Files.isRegularFile(manifest, LinkOption.NOFOLLOW_LINKS)) {
      throw new InvalidBackupException("no manifest: the backup is incomplete");
    }
    String text = Files.readString(manifest, StandardCharsets.UTF_8);
    int end = text.lastIndexOf("end ");
    if (end < 0 || !text.endsWith("\n")) {
      throw new InvalidBackupException("manifest is truncated");
    }
    String body = text.substring(0, end);
    if (!sha256(body.getBytes(StandardCharsets.UTF_8))
        .equals(text.substring(end + 4, text.length() - 1))) {
      throw new InvalidBackupException("manifest was modified");
    }
    String[] lines = body.split("\n", -1);
    if (lines.length < 4 || !lines[0].equals("shem-backup " + FORMAT)) {
      throw new InvalidBackupException("unsupported backup format");
    }
    List<Entry> entries = new ArrayList<>();
    for (int i = 4; i < lines.length; i++) {
      if (lines[i].isEmpty()) {
        continue;
      }
      String[] fields = lines[i].split(" ", 3);
      if (fields.length != 3) {
        throw new InvalidBackupException("manifest line " + (i + 1) + " is malformed");
      }
      Entry entry;
      try {
        entry = new Entry(fields[2], Long.parseLong(fields[1]), fields[0]);
      } catch (NumberFormatException e) {
        throw new InvalidBackupException("manifest line " + (i + 1) + " is malformed");
      }
      Path file = backup.resolve(entry.path()).normalize();
      if (!file.startsWith(backup) || !Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
        throw new InvalidBackupException("missing file: " + entry.path());
      }
      if (Files.size(file) != entry.size() || !sha256(file).equals(entry.sha256())) {
        throw new InvalidBackupException("altered file: " + entry.path());
      }
      entries.add(entry);
    }
    Set<String> listed = new java.util.HashSet<>();
    entries.forEach(e -> listed.add(e.path()));
    try (var walk = Files.walk(backup)) {
      for (Path file : (Iterable<Path>) walk.filter(Files::isRegularFile)::iterator) {
        String relative = backup.relativize(file).toString();
        if (!relative.equals(MANIFEST) && !listed.contains(relative)) {
          throw new InvalidBackupException("unlisted file: " + relative);
        }
      }
    }
    return entries;
  }

  /**
   * Restores into {@code target}, which must not exist or be empty. The backup is verified first;
   * files are copied into a staging directory, re-hashed, and the staging directory is renamed into
   * place only when complete, so a crash never leaves a half-restored data directory.
   */
  static List<Entry> restore(Path backup, Path target) throws IOException, InvalidBackupException {
    List<Entry> entries = verify(backup);
    if (Files.exists(target)) {
      try (var children = Files.list(target)) {
        if (children.findAny().isPresent()) {
          throw new IOException("restore target is not empty");
        }
      }
      Files.delete(target);
    }
    Path staging = target.resolveSibling(target.getFileName() + ".restore-staging");
    deleteTree(staging);
    DurableFiles.createPrivateDirectories(staging);
    for (Entry entry : entries) {
      Path destination = staging.resolve(entry.path());
      DurableFiles.createPrivateDirectories(
          java.util.Objects.requireNonNull(destination.getParent()));
      if (!copy(backup.resolve(entry.path()), destination).equals(entry.sha256())) {
        deleteTree(staging);
        throw new InvalidBackupException("file changed during restore: " + entry.path());
      }
    }
    syncTree(staging);
    Files.move(staging, target, StandardCopyOption.ATOMIC_MOVE);
    DurableFiles.syncDirectory(
        java.util.Objects.requireNonNull(target.toAbsolutePath().getParent()));
    return entries;
  }

  /** Files to back up, in a stable order. */
  static List<Path> files(Path data, Scope scope) throws IOException {
    TreeMap<String, Path> out = new TreeMap<>();
    Files.walkFileTree(
        data,
        new SimpleFileVisitor<>() {
          @Override
          public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
            if (dir.equals(data)) {
              return FileVisitResult.CONTINUE;
            }
            String name = dir.getFileName().toString();
            Path top = data.relativize(dir).getName(0);
            boolean topLevel = data.relativize(dir).getNameCount() == 1;
            if (DERIVED.contains(name)
                || (topLevel && name.equals("spool"))
                || (topLevel && name.equals("queue") && !scope.includeQueue())
                || (topLevel && SECRETS.contains(name) && !scope.includeSecrets())
                || top.toString().endsWith(".restore-staging")) {
              return FileVisitResult.SKIP_SUBTREE;
            }
            return FileVisitResult.CONTINUE;
          }

          @Override
          public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
            String name = file.getFileName().toString();
            boolean topLevel = data.relativize(file).getNameCount() == 1;
            if (attrs.isRegularFile()
                && !name.startsWith(DurableFiles.TEMP_PREFIX)
                && !(topLevel && (name.equals("shem.lock") || name.equals(".extraction-canary")))) {
              out.put(data.relativize(file).toString(), file);
            }
            return FileVisitResult.CONTINUE;
          }
        });
    return new ArrayList<>(out.values());
  }

  private static String lines(List<Entry> entries) {
    StringBuilder out = new StringBuilder();
    for (Entry entry : entries) {
      if (entry.path().contains("\n")) {
        throw new IllegalArgumentException("unsupported file name");
      }
      out.append(entry.sha256())
          .append(' ')
          .append(entry.size())
          .append(' ')
          .append(entry.path())
          .append('\n');
    }
    return out.toString();
  }

  /** Copies owner-only and returns the SHA-256 of what was written. */
  private static String copy(Path source, Path destination) throws IOException {
    MessageDigest digest = sha256();
    Path temp = DurableFiles.createTemporarySibling(destination);
    try (InputStream in = Files.newInputStream(source);
        OutputStream out = Files.newOutputStream(temp)) {
      byte[] buffer = new byte[64 * 1024];
      int n;
      while ((n = in.read(buffer)) > 0) {
        digest.update(buffer, 0, n);
        out.write(buffer, 0, n);
      }
    }
    try (var channel =
        java.nio.channels.FileChannel.open(temp, java.nio.file.StandardOpenOption.WRITE)) {
      channel.force(true);
    }
    Files.move(temp, destination, StandardCopyOption.ATOMIC_MOVE);
    return HexFormat.of().formatHex(digest.digest());
  }

  private static void syncTree(Path root) throws IOException {
    try (var walk = Files.walk(root)) {
      for (Path dir : (Iterable<Path>) walk.filter(Files::isDirectory)::iterator) {
        DurableFiles.syncDirectory(dir);
      }
    }
  }

  static void deleteTree(Path path) throws IOException {
    if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
      return;
    }
    try (var walk = Files.walk(path)) {
      for (Path p : (Iterable<Path>) walk.sorted(java.util.Comparator.reverseOrder())::iterator) {
        Files.deleteIfExists(p);
      }
    }
  }

  static String sha256(Path file) throws IOException {
    MessageDigest digest = sha256();
    try (InputStream in = Files.newInputStream(file)) {
      byte[] buffer = new byte[64 * 1024];
      int n;
      while ((n = in.read(buffer)) > 0) {
        digest.update(buffer, 0, n);
      }
    }
    return HexFormat.of().formatHex(digest.digest());
  }

  private static String sha256(byte[] bytes) {
    return HexFormat.of().formatHex(sha256().digest(bytes));
  }

  private static MessageDigest sha256() {
    try {
      return MessageDigest.getInstance("SHA-256");
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 unavailable", e);
    }
  }
}
