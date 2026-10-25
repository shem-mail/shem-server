package org.shem.policy;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.apache.james.mime4j.dom.address.Address;
import org.apache.james.mime4j.dom.address.Group;
import org.apache.james.mime4j.dom.address.Mailbox;
import org.apache.james.mime4j.field.address.DefaultAddressParser;
import org.apache.james.mime4j.field.address.ParseException;

/** The header identities a submitted message claims, for sender authorization. */
public final class HeaderIdentities {
  private HeaderIdentities() {}

  /**
   * Addresses in the {@code From} and {@code Sender} fields, or empty if the header section is
   * unbounded or malformed, there is not exactly one {@code From} field, or it lists no address.
   */
  public static Optional<List<String>> authors(InputStream message) throws IOException {
    HeaderBlock headers = HeaderBlock.read(message);
    if (!headers.complete() || headers.values("From").size() != 1) {
      return Optional.empty();
    }
    List<String> addresses = new ArrayList<>();
    for (String name : List.of("From", "Sender")) {
      List<String> values = headers.values(name);
      if (values.size() > 1) {
        return Optional.empty();
      }
      for (String value : values) {
        try {
          for (Address address : DefaultAddressParser.DEFAULT.parseAddressList(value)) {
            if (address instanceof Mailbox mailbox) {
              addresses.add(mailbox.getAddress());
            } else if (address instanceof Group group) {
              group.getMailboxes().forEach(m -> addresses.add(m.getAddress()));
            }
          }
        } catch (ParseException | RuntimeException e) {
          return Optional.empty();
        }
      }
    }
    return addresses.isEmpty() ? Optional.empty() : Optional.of(List.copyOf(addresses));
  }
}
