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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class DevBootstrapCommandTest {
  @TempDir Path dir;

  private ShemConfig config(String mode, boolean dev) {
    Properties p = new Properties();
    p.setProperty("data.directory", "data");
    p.setProperty("mode", mode);
    p.setProperty("dev.bootstrap.enabled", String.valueOf(dev));
    p.setProperty("argon2.memoryKiB", String.valueOf(19 * 1024));
    p.setProperty("argon2.iterations", "1");
    return ShemConfig.fromProperties(p, dir);
  }

  private String run(ShemConfig config, String stdin, String... args) throws Exception {
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    PrintStream out = new PrintStream(bytes, true, StandardCharsets.UTF_8);
    int code =
        new DevBootstrapCommand(config, out, new BufferedReader(new StringReader(stdin)))
            .run(List.of(args));
    assertThat(code).as(bytes.toString(StandardCharsets.UTF_8)).isZero();
    return bytes.toString(StandardCharsets.UTF_8);
  }

  @Test
  void createsDomainAccountAndEnrollsThroughServices() throws Exception {
    ShemConfig config = config("development", true);
    run(config, "", "create-domain", "example.org");
    String created = run(config, "", "create-account", "alice@example.org");
    String bootstrap = created.lines().toList().get(1);
    assertThat(bootstrap).matches("[a-z2-7]{4}(-[a-z2-7]{4}){5}");
    String enrolled =
        run(config, bootstrap + "\ncorrect horse battery staple\n", "enroll", "alice@example.org");
    assertThat(enrolled).contains("enrolled; new key fingerprint");
    // The bootstrap password never reaches the data directory.
    try (var files = Files.walk(dir.resolve("data"))) {
      for (Path f : (Iterable<Path>) files::iterator) {
        if (Files.isRegularFile(f)) {
          assertThat(new String(Files.readAllBytes(f), StandardCharsets.ISO_8859_1))
              .doesNotContain(bootstrap);
        }
      }
    }
  }

  @Test
  void productionModeRejectsDevBootstrap() {
    assertThatThrownBy(() -> config("production", true))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void unknownConfigurationKeysFailClosed() {
    Properties p = new Properties();
    p.setProperty("data.directory", "data");
    p.setProperty("smtp.allowOpenRelay", "true");
    assertThatThrownBy(() -> ShemConfig.fromProperties(p, dir)).hasMessageContaining("unknown");
  }

  @Test
  void dataDirectoryLockPreventsConcurrentProcesses() throws Exception {
    ShemConfig config = config("development", true);
    try (DataDirectory held = DataDirectory.open(config.dataDirectory())) {
      assertThat(held.root()).exists();
      assertThatThrownBy(() -> Services.start(config)).isInstanceOf(java.io.IOException.class);
    }
  }
}
