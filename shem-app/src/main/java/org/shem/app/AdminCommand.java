package org.shem.app;

import java.io.BufferedReader;
import java.io.PrintStream;
import java.util.List;
import org.shem.crypto.Secret;
import org.shem.crypto.Totp;
import org.shem.identity.AdminStore;

/**
 * Offline administrator management (ADR 0016). Holds the data-directory lock, so it cannot run
 * beside a server and no admin session can outlive a deletion. Administrators manage domains and
 * accounts through the admin API; they never hold mailbox keys.
 */
final class AdminCommand {
  private final ShemConfig config;
  private final PrintStream out;
  private final BufferedReader in;

  AdminCommand(ShemConfig config, PrintStream out, BufferedReader in) {
    this.config = config;
    this.out = out;
    this.in = in;
  }

  int run(List<String> args) throws Exception {
    if (args.isEmpty()) {
      return usage();
    }
    try (Services services = Services.start(config)) {
      AdminStore admins = services.admins;
      switch (args.get(0)) {
        case "create" -> {
          if (args.size() != 2) {
            return usage();
          }
          String password = DevBootstrapCommand.readSecret(out, in, "admin password: ");
          String repeated = DevBootstrapCommand.readSecret(out, in, "repeat password: ");
          if (!password.equals(repeated)) {
            out.println("passwords do not match");
            return 1;
          }
          services.audit.record("cli", "admin.create", args.get(1), "attempt");
          try (Secret totp = admins.create(args.get(1), password)) {
            services.audit.record("cli", "admin.create", args.get(1), "ok");
            String secret = Totp.base32(totp);
            out.println("administrator created; enroll this TOTP secret now (shown once):");
            out.println(secret);
            out.println(
                "otpauth://totp/Shem:"
                    + args.get(1)
                    + "?secret="
                    + secret
                    + "&issuer=Shem&algorithm=SHA1&digits=6&period=30");
          } catch (AdminStore.AdminException e) {
            services.audit.record("cli", "admin.create", args.get(1), "failed");
            out.println("cannot create administrator: " + e.getMessage());
            return 1;
          }
        }
        case "audit-verify" -> {
          if (args.size() != 1) {
            return usage();
          }
          // Opening Services already verified the chain; report its length.
          out.println("audit log intact: " + services.audit.size() + " records");
        }
        case "list" -> {
          if (args.size() != 1) {
            return usage();
          }
          List<String> pending = admins.namesPendingSetup();
          for (String name : admins.names()) {
            out.println(pending.contains(name) ? name + " (setup pending)" : name);
          }
        }
        case "delete" -> {
          if (args.size() != 2) {
            return usage();
          }
          services.audit.record("cli", "admin.delete", args.get(1), "attempt");
          try {
            admins.delete(args.get(1));
            services.audit.record("cli", "admin.delete", args.get(1), "ok");
          } catch (AdminStore.AdminException e) {
            services.audit.record("cli", "admin.delete", args.get(1), "failed");
            out.println("cannot delete administrator: " + e.getMessage());
            return 1;
          }
          out.println("administrator deleted");
          if (admins.isEmpty()) {
            out.println("no administrators remain; create one before using the admin API");
          }
        }
        default -> {
          return usage();
        }
      }
    }
    return 0;
  }

  private int usage() {
    out.println("usage: shem admin <create NAME | list | delete NAME | audit-verify>");
    return 2;
  }
}
