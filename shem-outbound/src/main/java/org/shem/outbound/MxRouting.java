package org.shem.outbound;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import org.shem.policy.DnsResolver;

/**
 * RFC 5321 section 5.1 routing: MX hosts by preference (random order is not applied within equal
 * preferences; ties keep DNS order), the implicit MX (the domain's own address) when no MX exists,
 * and RFC 7505 null MX as a permanent refusal.
 */
final class MxRouting {
  static final int MAX_HOSTS = 10;

  /** Where mail for a domain goes. */
  sealed interface Route {}

  /** Deliver to these hosts in order. */
  record Hosts(List<String> hosts) implements Route {}

  /** The domain accepts no mail (null MX). */
  record NoMail() implements Route {}

  private final DnsResolver resolver;

  MxRouting(DnsResolver resolver) {
    this.resolver = resolver;
  }

  Route route(String domain) throws DnsResolver.DnsTemporaryException {
    List<String> records = resolver.lookup(domain, DnsResolver.Type.MX);
    if (records.isEmpty()) {
      return new Hosts(List.of(domain.toLowerCase(Locale.ROOT)));
    }
    List<String[]> parsed = new ArrayList<>();
    for (String record : records) {
      int space = record.indexOf(' ');
      if (space <= 0) {
        continue;
      }
      parsed.add(new String[] {record.substring(0, space), record.substring(space + 1).strip()});
    }
    if (parsed.size() == 1 && parsed.getFirst()[1].equals(".")) {
      return new NoMail();
    }
    List<String> hosts =
        parsed.stream()
            .filter(p -> !p[1].equals(".") && !p[1].isEmpty())
            .sorted(Comparator.comparingInt(p -> preference(p[0])))
            .map(p -> p[1].toLowerCase(Locale.ROOT))
            .distinct()
            .limit(MAX_HOSTS)
            .toList();
    return hosts.isEmpty() ? new NoMail() : new Hosts(hosts);
  }

  private static int preference(String value) {
    try {
      return Integer.parseInt(value);
    } catch (NumberFormatException e) {
      return Integer.MAX_VALUE;
    }
  }
}
