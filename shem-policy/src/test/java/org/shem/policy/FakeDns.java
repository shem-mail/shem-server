package org.shem.policy;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Deterministic in-memory DNS for policy tests. */
final class FakeDns implements DnsResolver {
  private final Map<String, List<String>> records = new HashMap<>();
  private final Set<String> failing = new HashSet<>();
  final List<String> queries = new ArrayList<>();

  FakeDns add(String name, Type type, String... values) {
    records.computeIfAbsent(key(name, type), k -> new ArrayList<>()).addAll(List.of(values));
    return this;
  }

  FakeDns fail(String name) {
    failing.add(name.toLowerCase(Locale.ROOT));
    return this;
  }

  @Override
  public List<String> lookup(String name, Type type) throws DnsTemporaryException {
    String normalized = name.toLowerCase(Locale.ROOT).replaceAll("\\.$", "");
    queries.add(normalized + "/" + type);
    if (failing.contains(normalized)) {
      throw new DnsTemporaryException("simulated SERVFAIL");
    }
    return List.copyOf(records.getOrDefault(key(normalized, type), List.of()));
  }

  private static String key(String name, Type type) {
    return name.toLowerCase(Locale.ROOT).replaceAll("\\.$", "") + "/" + type;
  }
}
