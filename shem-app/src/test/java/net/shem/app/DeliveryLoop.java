package net.shem.app;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.Properties;
import net.shem.common.OpaqueId;
import net.shem.delivery.DeliveryRequest;
import net.shem.delivery.MessageSource;
import net.shem.delivery.RecipientDelivery;
import net.shem.delivery.RecipientOutcome;
import net.shem.identity.EmailAddress;
import net.shem.store.DeliveryTarget;
import net.shem.store.SpecialUse;

/**
 * Child process for {@code KillDuringDeliveryIT}: delivers numbered messages to a locked mailbox
 * forever and prints {@code ACK n} only after delivery {@code n} returned success, which is the
 * moment SMTP would answer 250.
 */
public final class DeliveryLoop {
  private DeliveryLoop() {}

  static ShemConfig config(Path data) {
    Properties p = new Properties();
    p.setProperty("data.directory", data.toString());
    p.setProperty("mode", "development");
    p.setProperty("argon2.memoryKiB", String.valueOf(19 * 1024));
    p.setProperty("argon2.iterations", "1");
    return ShemConfig.fromProperties(p, data);
  }

  public static void main(String[] args) throws Exception {
    try (Services services = Services.start(config(Path.of(args[0])))) {
      var route = services.identity.resolveRecipient(EmailAddress.parse(args[1])).get(0);
      for (int i = 0; ; i++) {
        List<RecipientOutcome> outcomes =
            services.delivery.deliver(
                new DeliveryRequest(
                    OpaqueId.random(services.random),
                    List.of(
                        new RecipientDelivery(
                            route,
                            args[1],
                            new DeliveryTarget.Role(SpecialUse.INBOX),
                            0,
                            List.of(),
                            List.of())),
                    MessageSource.ofBytes(
                        ("Subject: MSG-" + i + "\r\n\r\nbody\r\n")
                            .getBytes(StandardCharsets.US_ASCII)),
                    System.currentTimeMillis(),
                    "bob@example.net"));
        if (outcomes.get(0) instanceof RecipientOutcome.Delivered) {
          System.out.println("ACK " + i);
          System.out.flush();
        }
      }
    }
  }
}
