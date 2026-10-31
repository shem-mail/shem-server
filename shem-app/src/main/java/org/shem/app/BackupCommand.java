package org.shem.app;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Path;
import java.time.Clock;
import java.util.List;
import org.shem.identity.AuditLog;

/**
 * {@code shem backup create DIR [--include-queue] [--exclude-secrets] | verify DIR} and {@code shem
 * restore DIR} (ADR 0020). Creating a backup takes the data-directory lock, so the server must be
 * stopped; restoring requires an absent or empty data directory.
 */
final class BackupCommand {
  private final ShemConfig config;
  private final PrintStream out;

  BackupCommand(ShemConfig config, PrintStream out) {
    this.config = config;
    this.out = out;
  }

  int backup(List<String> args) throws Exception {
    if (args.size() >= 2 && args.get(0).equals("create")) {
      Backup.Scope scope =
          new Backup.Scope(args.contains("--include-queue"), !args.contains("--exclude-secrets"));
      Path target = Path.of(args.get(1)).toAbsolutePath();
      try (DataDirectory data = DataDirectory.open(config.dataDirectory())) {
        audit(data.root(), "backup.create", "attempt");
        List<Backup.Entry> entries =
            Backup.create(data.root(), target, scope, Clock.systemUTC().instant());
        audit(data.root(), "backup.create", "ok");
        out.println("backup complete: " + entries.size() + " files");
        if (scope.includeSecrets()) {
          out.println(
              "WARNING: includes server secrets (DKIM, ACME, admin credentials); protect it"
                  + " separately, or use --exclude-secrets");
        }
        if (scope.includeQueue()) {
          out.println("WARNING: includes the plaintext outbound queue");
        }
      }
      return 0;
    }
    if (args.size() == 2 && args.get(0).equals("verify")) {
      try {
        out.println(
            "backup valid: "
                + Backup.verify(Path.of(args.get(1)).toAbsolutePath()).size()
                + " files");
        return 0;
      } catch (Backup.InvalidBackupException e) {
        out.println("backup INVALID: " + e.getMessage());
        return 1;
      }
    }
    out.println(
        "usage: shem backup <create DIR [--include-queue] [--exclude-secrets] | verify DIR>");
    return 2;
  }

  int restore(List<String> args) throws Exception {
    if (args.size() != 1) {
      out.println("usage: shem restore DIR");
      return 2;
    }
    Path target = config.dataDirectory();
    try {
      List<Backup.Entry> entries = Backup.restore(Path.of(args.get(0)).toAbsolutePath(), target);
      try (DataDirectory data = DataDirectory.open(target)) {
        audit(data.root(), "restore", "ok");
      }
      out.println("restored " + entries.size() + " files into " + target);
      out.println(
          "search indexes rebuild at each mailbox's next unlock; users sign in with their own"
              + " credentials (a restore cannot recover a lost password)");
      return 0;
    } catch (Backup.InvalidBackupException e) {
      out.println("restore refused, backup INVALID: " + e.getMessage());
      return 1;
    } catch (IOException e) {
      out.println("restore refused: " + e.getMessage());
      return 1;
    }
  }

  private static void audit(Path data, String action, String outcome)
      throws IOException, AuditLog.BrokenChainException {
    try (AuditLog log =
        AuditLog.open(data.resolve("audit").resolve("audit.log"), Clock.systemUTC(), null)) {
      log.record("cli", action, "-", outcome);
    }
  }
}
