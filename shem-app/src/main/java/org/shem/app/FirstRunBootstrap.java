package org.shem.app;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Arrays;
import org.shem.crypto.CryptoException;
import org.shem.crypto.KdfAdmission;
import org.shem.identity.AdminStore;
import org.shem.identity.IdentityException;

/**
 * First-run bootstrap (ADR 0021). When {@code serve} starts on a data directory that has neither a
 * routing directory nor an admin store, this creates the initial administrator in setup state (it
 * must replace the password and enroll TOTP at first login) and, optionally, the first mail domain.
 * On any other data directory it does nothing, so a configured initial password is meaningless once
 * the server has been initialized, and deleting the last administrator never revives it.
 */
final class FirstRunBootstrap {
  /** Why the bootstrap could not run; the message is safe to print. */
  static final class BootstrapException extends Exception {
    private static final long serialVersionUID = 1L;

    BootstrapException(String message) {
      super(message);
    }

    BootstrapException(String message, Throwable cause) {
      super(message, cause);
    }
  }

  private static final int MAX_PASSWORD_FILE_BYTES = 4096;
  private static final String ACTOR = "bootstrap";

  private final Services services;
  private final PrintStream out;

  FirstRunBootstrap(Services services, PrintStream out) {
    this.services = services;
    this.out = out;
  }

  /** True when the data directory has never held identities or administrators. */
  static boolean isFresh(DataDirectory data) {
    return !Files.exists(data.routingFile()) && !Files.exists(data.adminFile());
  }

  /**
   * Runs the bootstrap if it applies. Returns true when it created the administrator.
   *
   * @throws BootstrapException if the bootstrap applies but cannot complete; startup must stop
   */
  boolean run() throws BootstrapException, IOException, InterruptedException {
    ShemConfig.Bootstrap config = services.config.bootstrap();
    if (!config.enabled()) {
      return false;
    }
    if (!isFresh(services.data)) {
      if (config.adminPasswordFile() != null || config.domain() != null) {
        out.println("data directory already initialized; bootstrap.* settings are ignored");
      }
      return false;
    }
    Instant expires = services.clock.instant().plus(config.validity());
    Path passwordFile = config.adminPasswordFile();
    services.audit.record(ACTOR, "admin.create", config.adminName(), "attempt");
    try {
      if (passwordFile == null) {
        services.admins.createForSetupWithGeneratedPassword(config.adminName(), expires);
      } else {
        char[] password = readPassword(passwordFile);
        try {
          services.admins.createForSetup(config.adminName(), CharBuffer.wrap(password), expires);
        } finally {
          Arrays.fill(password, '\0');
        }
      }
    } catch (AdminStore.AdminException | CryptoException | KdfAdmission.Rejected e) {
      services.audit.record(ACTOR, "admin.create", config.adminName(), "failed");
      throw new BootstrapException("cannot create the initial administrator: " + e.getMessage(), e);
    } catch (BootstrapException e) {
      services.audit.record(ACTOR, "admin.create", config.adminName(), "failed");
      throw e;
    }
    services.audit.record(ACTOR, "admin.create", config.adminName(), "ok");
    out.println(
        "first run: created administrator '"
            + config.adminName()
            + "'; sign in at /api/v1/admin/auth/login to set a password and TOTP before "
            + expires);
    if (passwordFile == null) {
      out.println(
          "the initial password is in "
              + services.admins.initialPasswordFile()
              + " (deleted after setup)");
    }
    String domain = config.domain();
    if (domain != null) {
      createDomain(domain);
    }
    return true;
  }

  private void createDomain(String domain) throws IOException {
    services.audit.record(ACTOR, "domains.post", "-", "attempt");
    try {
      var created = services.identity.createDomain(domain);
      services.audit.record(ACTOR, "domains.post", created.domainId().toString(), "ok");
      out.println("first run: created mail domain " + domain);
    } catch (IdentityException e) {
      // The administrator exists; the domain can still be created through the admin API.
      services.audit.record(ACTOR, "domains.post", "-", "failed");
      out.println("first run: could not create mail domain; create it through the admin API");
    }
  }

  /**
   * Reads the initial password as characters without an intermediate {@code String}. One trailing
   * line ending is removed, so files written by {@code echo} or editors work.
   */
  private static char[] readPassword(Path file) throws BootstrapException, IOException {
    byte[] bytes;
    try {
      if (Files.size(file) > MAX_PASSWORD_FILE_BYTES) {
        throw new BootstrapException("bootstrap.adminPasswordFile is too large");
      }
      bytes = Files.readAllBytes(file);
    } catch (NoSuchFileException e) {
      throw new BootstrapException("bootstrap.adminPasswordFile does not exist", e);
    }
    try {
      int length = bytes.length;
      if (length > 0 && bytes[length - 1] == '\n') {
        length--;
      }
      if (length > 0 && bytes[length - 1] == '\r') {
        length--;
      }
      CharBuffer decoded;
      try {
        decoded =
            StandardCharsets.UTF_8
                .newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes, 0, length));
      } catch (CharacterCodingException e) {
        throw new BootstrapException("bootstrap.adminPasswordFile is not valid UTF-8", e);
      }
      char[] password = new char[decoded.remaining()];
      decoded.get(password);
      if (decoded.hasArray()) {
        Arrays.fill(decoded.array(), '\0');
      }
      return password;
    } finally {
      Arrays.fill(bytes, (byte) 0);
    }
  }
}
