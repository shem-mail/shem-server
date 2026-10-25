package org.shem.app;

import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.shem.crypto.Secret;
import org.shem.identity.EmailAddress;
import org.shem.mailbox.Capability;
import org.shem.mailbox.MailboxLease;
import org.shem.mailbox.MailboxProvisioning;
import org.shem.outbound.DkimSigning;

/**
 * Local-only development bootstrap (PLAN.md, Phase 2): creates domains and accounts and performs
 * enrollment through the same identity/enrollment services the HTTP API will use. It runs only with
 * {@code dev.bootstrap.enabled=true} outside production mode, holds the data-directory lock (so it
 * cannot run beside a server), and never grants access to keys or plaintext: the bootstrap password
 * is printed once, and enrollment reads both passwords from the terminal.
 */
final class DevBootstrapCommand {
  private final ShemConfig config;
  private final PrintStream out;
  private final BufferedReader in;

  DevBootstrapCommand(ShemConfig config, PrintStream out, BufferedReader in) {
    this.config = config;
    this.out = out;
    this.in = in;
  }

  int run(List<String> args) throws Exception {
    if (!config.devBootstrapEnabled() || config.mode() == ShemConfig.Mode.PRODUCTION) {
      out.println("dev bootstrap is disabled (set dev.bootstrap.enabled=true in development mode)");
      return 2;
    }
    if (args.isEmpty()) {
      return usage();
    }
    try (Services services = Services.start(config)) {
      switch (args.get(0)) {
        case "create-domain" -> {
          if (args.size() != 2) {
            return usage();
          }
          services.identity.createDomain(args.get(1));
          out.println("domain created");
        }
        case "create-account" -> {
          if (args.size() != 2) {
            return usage();
          }
          MailboxProvisioning.Provisioned provisioned =
              services.provisioning.provision(
                  EmailAddress.parse(args.get(1)), 0, config.bootstrapValidity());
          try (Secret bootstrap = provisioned.bootstrapPassword()) {
            out.println(
                "account created; bootstrap password (shown once, expires in "
                    + config.bootstrapValidity()
                    + "):");
            out.println(new String(bootstrap.exposeCopy(), StandardCharsets.UTF_8));
          }
          out.println("key fingerprint: " + provisioned.account().publicKey().fingerprint());
        }
        case "enroll" -> {
          if (args.size() != 2) {
            return usage();
          }
          String bootstrap = readSecret("bootstrap password: ");
          String password = readSecret("new password: ");
          try (MailboxLease lease =
              services.sessions.authenticate(
                  args.get(1), bootstrap, InetAddress.getLoopbackAddress(), Capability.ENROLL)) {
            services.lifecycle.enroll(lease, password);
          }
          out.println(
              "enrolled; new key fingerprint: "
                  + services
                      .identity
                      .loginAccount(args.get(1))
                      .map(a -> a.publicKey().fingerprint())
                      .orElse("unavailable"));
        }
        case "app-password" -> {
          if (args.size() != 3) {
            return usage();
          }
          String password = readSecret("password: ");
          try (MailboxLease lease =
                  services.sessions.authenticatePrimary(
                      args.get(1), password, InetAddress.getLoopbackAddress());
              Secret app = services.lifecycle.createAppPassword(lease, args.get(2))) {
            out.println("app password for IMAP and SMTP (shown once):");
            out.println(new String(app.exposeCopy(), StandardCharsets.UTF_8));
          }
        }
        case "dkim-key" -> {
          if (args.size() != 3) {
            return usage();
          }
          String domain = EmailAddress.canonicalDomain(args.get(1));
          String selector = args.get(2);
          if (!selector.matches("[a-z0-9][a-z0-9-]{0,62}")) {
            out.println("selector must be lower-case letters, digits, and hyphens");
            return 2;
          }
          var existing = services.identity.directory().domainByName(domain).orElse(null);
          if (existing == null) {
            out.println("unknown domain");
            return 2;
          }
          String record =
              new DkimSigning(services.data.dkimKeys(), services.identity)
                  .generate(selector, domain);
          services.identity.setDkimSelector(existing.domainId(), selector);
          out.println("publish this TXT record, then mail from " + domain + " is signed:");
          out.println(selector + "._domainkey." + domain + " IN TXT \"" + record + "\"");
        }
        default -> {
          return usage();
        }
      }
    }
    return 0;
  }

  // Null on JDK 21 without a terminal; on JDK 22+ a non-null console also serves piped input.
  @SuppressWarnings("SystemConsoleNull")
  private String readSecret(String prompt) throws IOException {
    Console console = System.console();
    if (console != null) {
      char[] chars = console.readPassword("%s", prompt);
      if (chars == null) {
        throw new IOException("no input");
      }
      return new String(chars);
    }
    out.print(prompt);
    out.flush();
    String line = in.readLine();
    if (line == null) {
      throw new IOException("no input");
    }
    return line;
  }

  private int usage() {
    out.println(
        "usage: shem dev <create-domain DOMAIN | create-account ADDRESS | enroll ADDRESS"
            + " | app-password ADDRESS LABEL | dkim-key DOMAIN SELECTOR>");
    return 2;
  }

  static BufferedReader stdin() {
    return new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
  }
}
