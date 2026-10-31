package org.shem.app;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.shem.crypto.Secret;
import org.shem.identity.EmailAddress;
import org.shem.mailbox.Capability;
import org.shem.mailbox.MailboxLease;
import org.shem.mailbox.MailboxProvisioning;
import org.shem.store.SpecialUse;
import org.shem.store.metadata.Folder;
import org.shem.store.metadata.MessageKey;

/**
 * Real process crashes: SIGKILL a delivering JVM at random points and check that every delivery it
 * acknowledged is present exactly once after restart (PLAN Phase 2 durability; ADR 0020).
 */
class KillDuringDeliveryIT {
  private static final String ALICE = "alice@example.org";
  private static final String PASSWORD = "correct horse battery staple";
  private static final InetAddress CLIENT = InetAddress.getLoopbackAddress();
  @TempDir Path dir;

  private void enroll(Path data) throws Exception {
    try (Services services = Services.start(DeliveryLoop.config(data))) {
      services.identity.createDomain("example.org");
      MailboxProvisioning.Provisioned provisioned =
          services.provisioning.provision(EmailAddress.parse(ALICE), 0, Duration.ofDays(1));
      String bootstrap;
      try (Secret secret = provisioned.bootstrapPassword()) {
        bootstrap = new String(secret.exposeCopy(), StandardCharsets.UTF_8);
      }
      try (MailboxLease lease =
          services.sessions.authenticate(ALICE, bootstrap, CLIENT, Capability.ENROLL)) {
        services.lifecycle.enroll(lease, PASSWORD);
      }
    }
  }

  /** Runs the delivery loop until {@code acks} acknowledgements, then SIGKILLs it. */
  private static Set<Integer> deliverAndKill(Path data, int acks) throws Exception {
    Process child =
        new ProcessBuilder(
                Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "-XX:-CreateCoredumpOnCrash",
                "-cp",
                System.getProperty("java.class.path"),
                DeliveryLoop.class.getName(),
                data.toString(),
                ALICE)
            .redirectError(ProcessBuilder.Redirect.DISCARD)
            .start();
    Set<Integer> acknowledged = new HashSet<>();
    try (BufferedReader out =
        new BufferedReader(
            new InputStreamReader(child.getInputStream(), StandardCharsets.US_ASCII))) {
      String line;
      while (acknowledged.size() < acks && (line = out.readLine()) != null) {
        if (line.startsWith("ACK ")) {
          acknowledged.add(Integer.parseInt(line.substring(4)));
        }
      }
      child.destroyForcibly(); // SIGKILL: no shutdown hooks, no flushing
      child.waitFor();
    }
    return acknowledged;
  }

  private static List<String> subjects(Path data) throws Exception {
    try (Services services = Services.start(DeliveryLoop.config(data));
        MailboxLease lease =
            services.sessions.authenticate(ALICE, PASSWORD, CLIENT, Capability.MAIL_ACCESS)) {
      Folder inbox = lease.read(v -> v.folderByRole(SpecialUse.INBOX).orElseThrow());
      List<String> out = new ArrayList<>();
      for (long uid : lease.read(v -> v.uids(inbox.folderId()))) {
        var record =
            lease.read(v -> v.message(new MessageKey(inbox.folderId(), uid))).orElseThrow();
        try (InputStream in = lease.openMessage(record)) {
          String text = new String(in.readAllBytes(), StandardCharsets.US_ASCII);
          out.add(text.substring(text.indexOf("Subject: ") + 9, text.indexOf("\r\n\r\n")));
        }
      }
      return out;
    }
  }

  @Test
  void acknowledgedDeliveriesSurviveSigkillExactlyOnce() throws Exception {
    Random random = new Random(7);
    for (int round = 0; round < 3; round++) {
      Path data = dir.resolve("data" + round);
      enroll(data);
      int wanted = 5 + random.nextInt(25);
      Set<Integer> acknowledged = deliverAndKill(data, wanted);
      assertThat(acknowledged).as("the child delivered until it was killed").hasSize(wanted);
      List<String> stored = subjects(data);
      assertThat(new HashSet<>(stored)).as("no duplicates").hasSize(stored.size());
      for (int i : acknowledged) {
        assertThat(stored).as("round " + round + ": acknowledged MSG-" + i).contains("MSG-" + i);
      }
      // At most the one delivery in flight at the kill may also be present, unacknowledged.
      assertThat(stored.size()).isBetween(acknowledged.size(), acknowledged.size() + 1);
    }
  }
}
