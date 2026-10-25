package org.shem.policy;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import org.shem.crypto.CryptoException;
import org.shem.crypto.Purpose;
import org.shem.crypto.SymmetricKey;

/**
 * In-memory greylisting by (client network, envelope sender, recipient). Entries are keyed by a
 * fingerprint under a key generated per process, so the table never holds addresses; it is bounded
 * (least-recently-used eviction) and lost on restart, which only means a sender is greylisted
 * again. Client networks are IPv4 /24 and IPv6 /64, tolerating sender pools.
 */
public final class Greylist {
  /** Timing and size settings. */
  public record Settings(
      Duration delay, Duration retryWindow, Duration passLifetime, int maxEntries) {
    public static final Settings DEFAULT =
        new Settings(Duration.ofMinutes(5), Duration.ofHours(4), Duration.ofDays(35), 100_000);
  }

  private record Entry(Instant firstSeen, Instant expires, boolean passed) {}

  private final Settings settings;
  private final Clock clock;
  private final SymmetricKey key;
  private final Map<ByteBuffer, Entry> entries;

  public Greylist(Settings settings, Clock clock, SecureRandom random) {
    this.settings = settings;
    this.clock = clock;
    this.key = SymmetricKey.generate(random);
    this.entries =
        new LinkedHashMap<>(1024, 0.75f, true) {
          private static final long serialVersionUID = 1L;

          @Override
          protected boolean removeEldestEntry(Map.Entry<ByteBuffer, Entry> eldest) {
            return size() > settings.maxEntries();
          }
        };
  }

  /** Whether this triplet may proceed now; the first attempt and early retries are deferred. */
  public boolean admit(InetAddress client, String sender, String recipient) throws CryptoException {
    ByteBuffer id = ByteBuffer.wrap(fingerprint(client, sender, recipient));
    Instant now = clock.instant();
    synchronized (entries) {
      Entry entry = entries.get(id);
      if (entry == null || now.isAfter(entry.expires())) {
        entries.put(id, new Entry(now, now.plus(settings.retryWindow()), false));
        return false;
      }
      if (entry.passed()) {
        entries.put(id, new Entry(entry.firstSeen(), now.plus(settings.passLifetime()), true));
        return true;
      }
      if (Duration.between(entry.firstSeen(), now).compareTo(settings.delay()) < 0) {
        return false;
      }
      entries.put(id, new Entry(entry.firstSeen(), now.plus(settings.passLifetime()), true));
      return true;
    }
  }

  int size() {
    synchronized (entries) {
      return entries.size();
    }
  }

  private byte[] fingerprint(InetAddress client, String sender, String recipient)
      throws CryptoException {
    byte[] address = client.getAddress();
    int prefix = client instanceof Inet4Address ? 3 : 8;
    ByteBuffer data =
        ByteBuffer.allocate(1 + prefix + 2 + 4 * (sender.length() + recipient.length()));
    data.put((byte) prefix).put(address, 0, prefix).put((byte) 0);
    data.put(sender.toLowerCase(Locale.ROOT).getBytes(StandardCharsets.UTF_8)).put((byte) 0);
    data.put(recipient.toLowerCase(Locale.ROOT).getBytes(StandardCharsets.UTF_8));
    byte[] bytes = new byte[data.position()];
    data.flip().get(bytes);
    return key.fingerprint(Purpose.POLICY_FINGERPRINT, bytes);
  }
}
