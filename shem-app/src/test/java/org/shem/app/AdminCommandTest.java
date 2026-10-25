package org.shem.app;

import static org.assertj.core.api.Assertions.assertThat;

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

class AdminCommandTest {
  private static final String PASSWORD = "an administrator passphrase";
  @TempDir Path dir;

  private ShemConfig config() {
    Properties p = new Properties();
    p.setProperty("data.directory", "data");
    p.setProperty("mode", "production");
    p.setProperty("argon2.memoryKiB", String.valueOf(19 * 1024));
    p.setProperty("argon2.iterations", "1");
    return ShemConfig.fromProperties(p, dir);
  }

  private record Result(int code, String out) {}

  private Result run(String stdin, String... args) throws Exception {
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    PrintStream out = new PrintStream(bytes, true, StandardCharsets.UTF_8);
    int code =
        new AdminCommand(config(), out, new BufferedReader(new StringReader(stdin)))
            .run(List.of(args));
    return new Result(code, bytes.toString(StandardCharsets.UTF_8));
  }

  @Test
  void createsListsAndDeletesAdministratorsInProductionMode() throws Exception {
    Result created = run(PASSWORD + "\n" + PASSWORD + "\n", "create", "root");
    assertThat(created.code()).as(created.out()).isZero();
    assertThat(created.out()).containsPattern("\\n[A-Z2-7]{32}\\n").contains("otpauth://totp/");
    assertThat(run("", "list").out()).isEqualTo("root" + System.lineSeparator());
    // Neither the password nor the TOTP secret is stored in the clear.
    String secret = created.out().lines().toList().get(1);
    try (Stream<Path> files = Files.walk(dir)) {
      for (Path file : files.filter(Files::isRegularFile).toList()) {
        String content = new String(Files.readAllBytes(file), StandardCharsets.ISO_8859_1);
        assertThat(content).doesNotContain(PASSWORD).doesNotContain(secret);
      }
    }
    Result deleted = run("", "delete", "root");
    assertThat(deleted.out()).contains("administrator deleted").contains("no administrators");
    assertThat(run("", "list").out()).isEmpty();
  }

  @Test
  void rejectsMismatchedShortOrDuplicatePasswords() throws Exception {
    assertThat(run(PASSWORD + "\nsomething else entirely\n", "create", "root").code()).isEqualTo(1);
    assertThat(run("short\nshort\n", "create", "root").out()).contains("at least 14");
    assertThat(run(PASSWORD + "\n" + PASSWORD + "\n", "create", "root").code()).isZero();
    assertThat(run(PASSWORD + "\n" + PASSWORD + "\n", "create", "root").out()).contains("exists");
    assertThat(run("", "delete", "nobody").code()).isEqualTo(1);
    assertThat(run("", "bogus").code()).isEqualTo(2);
  }
}
