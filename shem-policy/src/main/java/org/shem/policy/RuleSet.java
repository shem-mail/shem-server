package org.shem.policy;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A validated, immutable set of content rules. Each rule is a case-insensitive literal substring
 * test over decoded headers, body text, or both, with a score. There is deliberately no regex
 * support: matching is linear in the scanned text, so a rules update cannot cause catastrophic
 * backtracking (ADR 0010). Rules never learn from mail.
 *
 * <p>Format, one rule per line ({@code #} starts a comment):
 *
 * <pre>NAME header|body|any "literal" score</pre>
 */
public final class RuleSet {
  static final int MAX_RULES = 1000;
  static final int MAX_LITERAL = 200;
  private static final Pattern LINE =
      Pattern.compile(
          "([A-Z][A-Z0-9_]{0,63})\\s+(header|body|any)\\s+\"((?:[^\"\\\\]|\\\\.)*)\"\\s+(-?\\d{1,3}(?:\\.\\d{1,2})?)");

  /** Where a rule looks. */
  enum Scope {
    HEADER,
    BODY,
    ANY
  }

  record Rule(String name, Scope scope, String literal, double score) {}

  private final List<Rule> rules;

  private RuleSet(List<Rule> rules) {
    this.rules = List.copyOf(rules);
  }

  public static RuleSet empty() {
    return new RuleSet(List.of());
  }

  /** Parses and validates a whole rules file; nothing is accepted if any line is invalid. */
  public static RuleSet parse(List<String> lines) throws RuleSyntaxException {
    List<Rule> rules = new ArrayList<>();
    Set<String> names = new HashSet<>();
    for (int i = 0; i < lines.size(); i++) {
      String line = lines.get(i).strip();
      if (line.isEmpty() || line.startsWith("#")) {
        continue;
      }
      Matcher m = LINE.matcher(line);
      if (!m.matches()) {
        throw new RuleSyntaxException(i + 1, "expected: NAME header|body|any \"literal\" score");
      }
      String literal = m.group(3).replaceAll("\\\\(.)", "$1");
      if (literal.length() < 3 || literal.length() > MAX_LITERAL) {
        throw new RuleSyntaxException(
            i + 1, "literal must have 3 to " + MAX_LITERAL + " characters");
      }
      double score = Double.parseDouble(m.group(4));
      if (score < -100 || score > 100) {
        throw new RuleSyntaxException(i + 1, "score must be between -100 and 100");
      }
      if (!names.add(m.group(1))) {
        throw new RuleSyntaxException(i + 1, "duplicate rule name");
      }
      if (rules.size() >= MAX_RULES) {
        throw new RuleSyntaxException(i + 1, "more than " + MAX_RULES + " rules");
      }
      rules.add(
          new Rule(
              m.group(1),
              Scope.valueOf(m.group(2).toUpperCase(Locale.ROOT)),
              literal.toUpperCase(Locale.ROOT),
              score));
    }
    return new RuleSet(rules);
  }

  public int size() {
    return rules.size();
  }

  /** Names of matching rules, added to {@code hits}; returns the total score. */
  double apply(String upperHeaders, String upperBody, List<String> hits) {
    double score = 0;
    for (Rule rule : rules) {
      boolean match =
          switch (rule.scope()) {
            case HEADER -> upperHeaders.contains(rule.literal());
            case BODY -> upperBody.contains(rule.literal());
            case ANY -> upperHeaders.contains(rule.literal()) || upperBody.contains(rule.literal());
          };
      if (match) {
        hits.add(rule.name());
        score += rule.score();
      }
    }
    return score;
  }

  /** A rules file failed validation; the previous rules stay active. */
  public static final class RuleSyntaxException extends Exception {
    private static final long serialVersionUID = 1L;

    RuleSyntaxException(int line, String message) {
      super("rules line " + line + ": " + message);
    }
  }
}
