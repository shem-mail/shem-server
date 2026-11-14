package net.shem.mailbox;

import java.util.List;
import net.shem.store.metadata.MetadataChange;
import org.jspecify.annotations.Nullable;

/**
 * Notified, in commit order, after every committed mailbox change (imports, appends, flag changes,
 * folder operations) from any session. {@code origin} is the token the writer passed, letting a
 * session recognize its own changes. Must not block or write to the mailbox.
 */
@FunctionalInterface
public interface ChangeListener {
  void changed(long txSeq, @Nullable Object origin, List<MetadataChange> changes);
}
