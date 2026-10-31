package org.shem.policy;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.util.List;
import org.jspecify.annotations.Nullable;

/**
 * A content-rules file applied to an {@link InboundPolicy}. The initial load must succeed; later
 * reloads replace the active rules atomically only when the whole file validates, otherwise the
 * last known good rules stay active. Files larger than {@link #MAX_BYTES} are refused.
 */
public final class RulesFile {
  static final long MAX_BYTES = 1 << 20;

  /** Result of a reload check (safe to log). */
  public enum Reload {
    UNCHANGED,
    RELOADED,
    REJECTED
  }

  private final Path path;
  private final InboundPolicy policy;
  private @Nullable FileTime loaded;
  private @Nullable String lastError;

  public RulesFile(Path path, InboundPolicy policy) {
    this.path = path;
    this.policy = policy;
  }

  /** Loads the file for start-up; an invalid file fails start-up. */
  public synchronized void load() throws IOException, RuleSet.RuleSyntaxException {
    FileTime modified = Files.getLastModifiedTime(path);
    policy.replaceRules(parse());
    loaded = modified;
    lastError = null;
  }

  /** Reloads if the file changed since the last successful or rejected load. */
  public synchronized Reload reloadIfChanged() {
    FileTime modified;
    try {
      modified = Files.getLastModifiedTime(path);
    } catch (IOException e) {
      lastError = "rules file unreadable";
      return Reload.REJECTED;
    }
    if (modified.equals(loaded)) {
      return Reload.UNCHANGED;
    }
    loaded = modified;
    try {
      policy.replaceRules(parse());
      lastError = null;
      return Reload.RELOADED;
    } catch (IOException e) {
      lastError = "rules file unreadable";
      return Reload.REJECTED;
    } catch (RuleSet.RuleSyntaxException e) {
      lastError = e.getMessage();
      return Reload.REJECTED;
    }
  }

  /** Why the last reload was rejected (line number and reason, never rule contents). */
  public synchronized @Nullable String lastError() {
    return lastError;
  }

  private RuleSet parse() throws IOException, RuleSet.RuleSyntaxException {
    if (Files.size(path) > MAX_BYTES) {
      throw new IOException("rules file too large");
    }
    List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);
    return RuleSet.parse(lines);
  }
}
