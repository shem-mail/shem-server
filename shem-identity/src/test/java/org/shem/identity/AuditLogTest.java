package org.shem.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Clock;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AuditLogTest {
  @TempDir Path dir;

  private Path file() {
    return dir.resolve("audit/audit.log");
  }

  @Test
  void recordsChainAcrossReopenAndMirror() throws Exception {
    ByteArrayOutputStream mirror = new ByteArrayOutputStream();
    try (AuditLog log =
        AuditLog.open(
            file(), Clock.systemUTC(), new PrintStream(mirror, true, StandardCharsets.UTF_8))) {
      log.record("admin:root", "domain.create", "-", "attempt");
      log.record("admin:root", "domain.create", "0123abcd", "ok");
    }
    try (AuditLog log = AuditLog.open(file(), Clock.systemUTC(), null)) {
      assertThat(log.size()).isEqualTo(2);
      log.record("system", "account.key-changed", "beef", "ok");
    }
    assertThat(AuditLog.verifyFile(file())).isEqualTo(3);
    assertThat(mirror.toString(StandardCharsets.UTF_8).lines())
        .hasSize(2)
        .allMatch(l -> l.startsWith("audit v1 "));
    assertThat(Files.getPosixFilePermissions(file()))
        .containsExactlyInAnyOrder(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
  }

  @Test
  void freeTextNeverEntersARecord() throws Exception {
    try (AuditLog log = AuditLog.open(file(), Clock.systemUTC(), null)) {
      log.record("alice@example.org secret subject", "x y", "line\nbreak", "ok");
    }
    String text = Files.readString(file());
    assertThat(text)
        .doesNotContain("secret")
        .doesNotContain("break")
        .contains(" invalid invalid invalid ok ");
  }

  @Test
  void editsAndDeletionsInsideTheFileAreDetected() throws Exception {
    try (AuditLog log = AuditLog.open(file(), Clock.systemUTC(), null)) {
      for (int i = 0; i < 3; i++) {
        log.record("admin:root", "alias.delete", "id" + i, "ok");
      }
    }
    List<String> lines = Files.readAllLines(file());
    Files.writeString(file(), lines.get(0) + "\n" + lines.get(2) + "\n");
    assertThatThrownBy(() -> AuditLog.verifyFile(file()))
        .isInstanceOf(AuditLog.BrokenChainException.class)
        .hasMessageContaining("chain broken at record 2");
    Files.writeString(
        file(),
        lines.get(0) + "\n" + lines.get(1).replace("id1", "id9") + "\n" + lines.get(2) + "\n");
    assertThatThrownBy(() -> AuditLog.open(file(), Clock.systemUTC(), null))
        .isInstanceOf(AuditLog.BrokenChainException.class)
        .hasMessageContaining("record 2 was modified");
  }

  @Test
  void aTornFinalWriteIsCutOff() throws Exception {
    try (AuditLog log = AuditLog.open(file(), Clock.systemUTC(), null)) {
      log.record("admin:root", "account.create", "-", "attempt");
    }
    Files.writeString(
        file(), "v1 2 2026-11-01T00:00:00Z admin:root acc", StandardOpenOption.APPEND);
    try (AuditLog log = AuditLog.open(file(), Clock.systemUTC(), null)) {
      assertThat(log.size()).isEqualTo(1);
      log.record("admin:root", "account.create", "-", "failed");
    }
    assertThat(AuditLog.verifyFile(file())).isEqualTo(2);
  }
}
