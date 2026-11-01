package org.shem.app;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Properties;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class FirstRunBootstrapTest {
  private static final String INITIAL = "initial passphrase from a secret";
  @TempDir Path dir;
  private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
  private final PrintStream out = new PrintStream(bytes, true, StandardCharsets.UTF_8);

  private ShemConfig config(String... keyValues) {
    Properties p = new Properties();
    p.setProperty("data.directory", "data");
    p.setProperty("mode", "production");
    p.setProperty("argon2.memoryKiB", String.valueOf(19 * 1024));
    p.setProperty("argon2.iterations", "1");
    for (int i = 0; i < keyValues.length; i += 2) {
      p.setProperty(keyValues[i], keyValues[i + 1]);
    }
    return ShemConfig.fromProperties(p, dir);
  }

  private boolean bootstrap(ShemConfig config) throws Exception {
    try (Services services = Services.start(config)) {
      return new FirstRunBootstrap(services, out).run();
    }
  }

  private String output() {
    return bytes.toString(StandardCharsets.UTF_8);
  }

  @Test
  void freshDataDirectoryGetsAnAdministratorFromThePasswordFileAndTheFirstDomain()
      throws Exception {
    Files.writeString(dir.resolve("admin-password"), INITIAL + "\n");
    ShemConfig config =
        config(
            "bootstrap.adminPasswordFile", "admin-password",
            "bootstrap.domain", "Example.ORG");
    assertThat(bootstrap(config)).isTrue();
    assertThat(output()).contains("created administrator 'admin'").contains("example.org");
    assertThat(output()).doesNotContain(INITIAL);

    try (Services services = Services.start(config)) {
      assertThat(services.admins.namesPendingSetup()).containsExactly("admin");
      try (var verified = services.admins.verifyPassword("admin", INITIAL).orElseThrow()) {
        assertThat(verified.setupRequired()).as("trailing newline removed").isTrue();
      }
      assertThat(services.identity.directory().domainByName("example.org")).isPresent();
      assertThat(services.admins.initialPasswordFile()).doesNotExist();
    }
    try (Stream<Path> files = Files.walk(dir.resolve("data"))) {
      for (Path file : files.filter(Files::isRegularFile).toList()) {
        String content = new String(Files.readAllBytes(file), StandardCharsets.ISO_8859_1);
        assertThat(content).as(file.toString()).doesNotContain(INITIAL);
      }
    }
  }

  @Test
  void laterStartsIgnoreTheBootstrapEvenWithoutAdministrators() throws Exception {
    Files.writeString(dir.resolve("admin-password"), INITIAL);
    ShemConfig config = config("bootstrap.adminPasswordFile", "admin-password");
    assertThat(bootstrap(config)).isTrue();

    // A new password file on a later start has no effect.
    Files.writeString(dir.resolve("admin-password"), "a different initial passphrase");
    assertThat(bootstrap(config)).isFalse();
    assertThat(output()).contains("already initialized");

    // Deleting the last administrator does not revive the bootstrap.
    ByteArrayOutputStream cli = new ByteArrayOutputStream();
    new AdminCommand(
            config,
            new PrintStream(cli, true, StandardCharsets.UTF_8),
            new BufferedReader(new StringReader("")))
        .run(List.of("delete", "admin"));
    assertThat(bootstrap(config)).isFalse();
    try (Services services = Services.start(config)) {
      assertThat(services.admins.isEmpty()).isTrue();
    }
  }

  @Test
  void administratorCreatedWithTheCliFirstSkipsTheBootstrap() throws Exception {
    ShemConfig config = config();
    String password = "an administrator passphrase";
    new AdminCommand(
            config,
            new PrintStream(new ByteArrayOutputStream(), true, StandardCharsets.UTF_8),
            new BufferedReader(new StringReader(password + "\n" + password + "\n")))
        .run(List.of("create", "root"));
    assertThat(bootstrap(config)).isFalse();
    try (Services services = Services.start(config)) {
      assertThat(services.admins.names()).containsExactly("root");
    }
  }

  @Test
  void withoutAPasswordFileAPasswordIsGeneratedIntoTheDataDirectory() throws Exception {
    ShemConfig config = config("bootstrap.adminName", "ops");
    assertThat(bootstrap(config)).isTrue();
    Path file = dir.resolve("data/admin/initial-password");
    String password = Files.readString(file).strip();
    assertThat(output()).contains(file.toString()).doesNotContain(password);
    try (Services services = Services.start(config)) {
      assertThat(services.admins.verifyPassword("ops", password)).isPresent();
    }
    ByteArrayOutputStream cli = new ByteArrayOutputStream();
    new AdminCommand(
            config,
            new PrintStream(cli, true, StandardCharsets.UTF_8),
            new BufferedReader(new StringReader("")))
        .run(List.of("list"));
    assertThat(cli.toString(StandardCharsets.UTF_8)).contains("ops (setup pending)");
  }

  @Test
  void disabledBootstrapCreatesNothing() throws Exception {
    assertThat(bootstrap(config("bootstrap.enabled", "false"))).isFalse();
    assertThat(dir.resolve("data/admin/admins.bin")).doesNotExist();
  }

  @Test
  void unusablePasswordFilesStopTheBootstrapWithoutCreatingAnAdministrator() throws Exception {
    ShemConfig missing = config("bootstrap.adminPasswordFile", "absent");
    assertThatThrownBy(() -> bootstrap(missing)).hasMessageContaining("does not exist");
    Files.writeString(dir.resolve("short"), "too short");
    ShemConfig tooShort = config("bootstrap.adminPasswordFile", "short");
    assertThatThrownBy(() -> bootstrap(tooShort)).hasMessageContaining("14");
    assertThat(dir.resolve("data/admin/admins.bin")).doesNotExist();
    try (Services services = Services.start(config())) {
      assertThat(FirstRunBootstrap.isFresh(services.data)).isTrue();
    }
  }
}
