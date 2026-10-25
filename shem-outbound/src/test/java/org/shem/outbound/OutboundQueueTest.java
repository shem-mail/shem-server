package org.shem.outbound;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Duration;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.shem.common.IdGenerator;
import org.shem.delivery.MessageSource;

class OutboundQueueTest {
  @TempDir Path dir;
  private final OutboundFixture.MutableClock clock = new OutboundFixture.MutableClock();

  private OutboundQueue open(int maxItems, long maxBytes) throws Exception {
    return OutboundQueue.open(
        dir.resolve("queue"),
        new OutboundQueue.Limits(maxItems, maxBytes, Duration.ofDays(5)),
        IdGenerator.secure(OutboundFixture.RANDOM),
        clock);
  }

  private static MessageSource message(String text) {
    return MessageSource.ofBytes(text.getBytes(StandardCharsets.UTF_8));
  }

  @Test
  void itemsSurviveRestartAndStateTransitionsAreDurable() throws Exception {
    OutboundQueue queue = open(10, 1 << 20);
    QueueItem item =
        queue.enqueue(
            "alice@example.org",
            List.of("a@example.net", "b@example.com"),
            message("Subject: x\r\n\r\nbody\r\n"));
    queue.update(
        item.withRecipients(
                List.of(
                    new QueueItem.Recipient(
                        "a@example.net", QueueItem.Status.DELIVERED, "250 2.0.0")))
            .rescheduled(clock.instant().plusSeconds(300), 1));

    OutboundQueue reopened = open(10, 1 << 20);
    QueueItem loaded = reopened.get(item.id()).orElseThrow();
    assertThat(loaded.attempts()).isEqualTo(1);
    assertThat(loaded.pending())
        .extracting(QueueItem.Recipient::address)
        .containsExactly("b@example.com");
    assertThat(reopened.due(clock.instant())).isEmpty();
    assertThat(reopened.due(clock.instant().plusSeconds(301))).hasSize(1);
    try (var in = reopened.openMessage(item.id())) {
      assertThat(new String(in.readAllBytes(), StandardCharsets.UTF_8))
          .isEqualTo("Subject: x\r\n\r\nbody\r\n");
    }
    reopened.remove(item.id());
    assertThat(open(10, 1 << 20).size()).isZero();
    try (Stream<Path> files = Files.list(dir.resolve("queue"))) {
      assertThat(files.toList()).isEmpty();
    }
  }

  @Test
  void crashLeftoversAreRemovedAndCorruptionFailsClosed() throws Exception {
    OutboundQueue queue = open(10, 1 << 20);
    QueueItem item = queue.enqueue("alice@example.org", List.of("a@example.net"), message("x"));
    Path queueDir = dir.resolve("queue");
    Files.writeString(queueDir.resolve("0123456789abcdef0123456789abcdef.eml"), "orphan message");
    Files.writeString(queueDir.resolve(".tmp-leftover"), "partial");
    OutboundQueue reopened = open(10, 1 << 20);
    assertThat(reopened.size()).isEqualTo(1);
    try (Stream<Path> files = Files.list(queueDir)) {
      assertThat(files.map(p -> p.getFileName().toString()).toList())
          .containsExactlyInAnyOrder(item.id() + ".eml", item.id() + ".state");
    }
    assertThat(Files.getPosixFilePermissions(queueDir))
        .doesNotContain(PosixFilePermission.GROUP_READ, PosixFilePermission.OTHERS_READ);

    Path state = queueDir.resolve(item.id() + ".state");
    byte[] bytes = Files.readAllBytes(state);
    bytes[4] = 99;
    Files.write(state, bytes);
    assertThatThrownBy(() -> open(10, 1 << 20)).hasMessageContaining("corrupt queue state");
  }

  @Test
  void admissionIsBoundedByItemsAndBytes() throws Exception {
    OutboundQueue queue = open(2, 100);
    queue.enqueue("a@example.org", List.of("x@example.net"), message("small"));
    assertThatThrownBy(
            () ->
                queue.enqueue("a@example.org", List.of("x@example.net"), message("y".repeat(200))))
        .isInstanceOf(OutboundQueue.QueueFullException.class);
    queue.enqueue("a@example.org", List.of("x@example.net"), message("small"));
    assertThatThrownBy(() -> queue.enqueue("a@example.org", List.of("x@example.net"), message("z")))
        .isInstanceOf(OutboundQueue.QueueFullException.class);
  }

  @Test
  void stateRecordRoundTrips() throws Exception {
    QueueItem item =
        new QueueItem(
            org.shem.common.OpaqueId.random(OutboundFixture.RANDOM),
            "",
            List.of(
                new QueueItem.Recipient("a@example.net", QueueItem.Status.FAILED, "550 5.1.1"),
                new QueueItem.Recipient("b@example.net", QueueItem.Status.PENDING, "")),
            clock.instant(),
            clock.instant().plusSeconds(10),
            clock.instant(),
            3,
            true);
    assertThat(OutboundQueue.decode(OutboundQueue.encode(item))).isEqualTo(item);
  }
}
