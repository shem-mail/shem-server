package org.shem.policy;

import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import org.apache.james.jspf.core.DNSRequest;
import org.apache.james.jspf.core.DNSService;
import org.apache.james.jspf.core.exceptions.TimeoutException;

/** jSPF's DNS interface over {@link DnsResolver}; jSPF never opens its own resolver. */
final class JspfDns implements DNSService {
  private final DnsResolver resolver;
  private int recordLimit = 10;

  JspfDns(DnsResolver resolver) {
    this.resolver = resolver;
  }

  @Override
  public List<String> getRecords(DNSRequest request) throws TimeoutException {
    if (request.getRecordType() == DNSRequest.SPF) {
      // RFC 7208 removed the SPF RR type; jSPF then falls back to TXT.
      return List.of();
    }
    DnsResolver.Type type =
        switch (request.getRecordType()) {
          case DNSRequest.A -> DnsResolver.Type.A;
          case DNSRequest.AAAA -> DnsResolver.Type.AAAA;
          case DNSRequest.MX -> DnsResolver.Type.MX;
          case DNSRequest.PTR -> DnsResolver.Type.PTR;
          case DNSRequest.TXT -> DnsResolver.Type.TXT;
          default -> throw new IllegalArgumentException("unsupported record type");
        };
    try {
      List<String> records = resolver.lookup(request.getHostname(), type);
      if (type == DnsResolver.Type.MX) {
        records =
            records.stream()
                .sorted(java.util.Comparator.comparingInt(JspfDns::preference))
                .map(r -> r.substring(r.indexOf(' ') + 1))
                .filter(host -> !host.equals("."))
                .toList();
      }
      if ((type == DnsResolver.Type.MX || type == DnsResolver.Type.PTR)
          && records.size() > recordLimit) {
        return records.subList(0, recordLimit);
      }
      return records;
    } catch (DnsResolver.DnsTemporaryException e) {
      throw new TimeoutException(e.getMessage());
    }
  }

  private static int preference(String mx) {
    try {
      return Integer.parseInt(mx.substring(0, mx.indexOf(' ')));
    } catch (RuntimeException e) {
      return Integer.MAX_VALUE;
    }
  }

  @Override
  public CompletionStage<List<String>> getRecordsAsync(DNSRequest request) {
    try {
      return CompletableFuture.completedFuture(getRecords(request));
    } catch (TimeoutException e) {
      return CompletableFuture.failedFuture(e);
    }
  }

  @Override
  public List<String> getLocalDomainNames() {
    return List.of();
  }

  @Override
  public void setTimeOut(int timeOut) {
    // Timeouts belong to the DnsResolver.
  }

  @Override
  public int getRecordLimit() {
    return recordLimit;
  }

  @Override
  public void setRecordLimit(int recordLimit) {
    this.recordLimit = recordLimit;
  }
}
