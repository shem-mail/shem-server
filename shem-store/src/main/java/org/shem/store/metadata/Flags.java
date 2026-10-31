package org.shem.store.metadata;

import java.util.List;
import java.util.Locale;
import java.util.TreeSet;

/** IMAP system flags (bit set) plus keywords. Immutable. */
public record Flags(int system, List<String> keywords) {
  public static final int SEEN = 1;
  public static final int ANSWERED = 2;
  public static final int FLAGGED = 4;
  public static final int DELETED = 8;
  public static final int DRAFT = 16;
  public static final int ALL_SYSTEM = SEEN | ANSWERED | FLAGGED | DELETED | DRAFT;
  public static final int MAX_KEYWORDS = 64;
  public static final Flags NONE = new Flags(0, List.of());

  public Flags {
    if ((system & ~ALL_SYSTEM) != 0) {
      throw new IllegalArgumentException("unknown system flag");
    }
    TreeSet<String> normalized = new TreeSet<>();
    for (String keyword : keywords) {
      if (!keyword.matches("[\\x21-\\x7e&&[^(){%*\"\\\\\\]]]{1,64}")) {
        throw new IllegalArgumentException("invalid keyword");
      }
      normalized.add(keyword);
    }
    if (normalized.size() > MAX_KEYWORDS) {
      throw new IllegalArgumentException("too many keywords");
    }
    keywords = List.copyOf(normalized);
  }

  public boolean has(int flag) {
    return (system & flag) != 0;
  }

  public boolean hasKeyword(String keyword) {
    for (String k : keywords) {
      if (k.toLowerCase(Locale.ROOT).equals(keyword.toLowerCase(Locale.ROOT))) {
        return true;
      }
    }
    return false;
  }

  public Flags plus(Flags other) {
    TreeSet<String> all = new TreeSet<>(keywords);
    all.addAll(other.keywords);
    return new Flags(system | other.system, List.copyOf(all));
  }

  public Flags minus(Flags other) {
    TreeSet<String> remaining = new TreeSet<>(keywords);
    other.keywords.forEach(remaining::remove);
    return new Flags(system & ~other.system, List.copyOf(remaining));
  }
}
