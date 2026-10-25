package org.shem.policy;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import org.apache.james.jdkim.DKIMVerifier;
import org.apache.james.jdkim.api.PublicKeyRecordRetriever;
import org.apache.james.jdkim.api.Result;
import org.apache.james.jdkim.api.SignatureRecord;
import org.apache.james.jdkim.exceptions.FailException;
import org.apache.james.jdkim.exceptions.PermFailException;
import org.apache.james.jdkim.exceptions.TempFailException;

/**
 * DKIM verification (RFC 6376) through jDKIM's streaming API: headers come from {@link HeaderBlock}
 * and the body is hashed as it streams, so the message is never fully buffered.
 */
final class DkimCheck {
  /** One signature's result. */
  record Outcome(AuthResult result, String domain, String selector) {}

  private final DnsResolver resolver;

  DkimCheck(DnsResolver resolver) {
    this.resolver = resolver;
  }

  /** Verifies the signatures of a message whose headers were read from {@code body}'s stream. */
  List<Outcome> verify(HeaderBlock headers, InputStream body) throws IOException {
    if (headers.getFields("DKIM-Signature").isEmpty()) {
      return List.of();
    }
    DKIMVerifier verifier = new DKIMVerifier(new Keys(resolver));
    try {
      verifier.verify(headers, body);
    } catch (FailException e) {
      // Per-signature results (including this failure) are in getResults().
    } catch (RuntimeException e) {
      return List.of(new Outcome(AuthResult.PERMERROR, "", ""));
    }
    List<Outcome> outcomes = new ArrayList<>();
    for (Result result : verifier.getResults()) {
      SignatureRecord record = result.getRecord();
      String domain =
          record == null || record.getDToken() == null ? "" : record.getDToken().toString();
      String selector =
          record == null || record.getSelector() == null ? "" : record.getSelector().toString();
      outcomes.add(new Outcome(map(result.getResultType()), domain, selector));
    }
    return outcomes;
  }

  private static AuthResult map(Result.Type type) {
    return switch (type) {
      case PASS -> AuthResult.PASS;
      case FAIL -> AuthResult.FAIL;
      case NEUTRAL -> AuthResult.NEUTRAL;
      case TEMPERROR -> AuthResult.TEMPERROR;
      case POLICY -> AuthResult.POLICY;
      case NONE -> AuthResult.NONE;
      default -> AuthResult.PERMERROR;
    };
  }

  /** Public keys from {@code selector._domainkey.domain} TXT records. */
  private record Keys(DnsResolver resolver) implements PublicKeyRecordRetriever {
    @Override
    public List<String> getRecords(
        CharSequence methodAndOption, CharSequence selector, CharSequence token)
        throws TempFailException, PermFailException {
      if (!"dns/txt".equalsIgnoreCase(methodAndOption.toString())) {
        throw new PermFailException("unsupported key query method");
      }
      try {
        return resolver.lookup(selector + "._domainkey." + token, DnsResolver.Type.TXT);
      } catch (DnsResolver.DnsTemporaryException e) {
        throw new TempFailException("key lookup failed");
      }
    }
  }
}
