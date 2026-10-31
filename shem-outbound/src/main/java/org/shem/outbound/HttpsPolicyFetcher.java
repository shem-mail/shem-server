package org.shem.outbound;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import org.shem.policy.DnsResolver;

/**
 * Fetches MTA-STS policies over HTTPS with certificate validation, no redirects, a time limit, and
 * a 64 KiB size limit. Before connecting, every address of {@code mta-sts.<domain>} must be a
 * public unicast address, so a hostile domain cannot point the fetch at internal services. The HTTP
 * client resolves the name again; that residual race is documented in ADR 0012. No message content
 * or recipient address is ever sent.
 */
final class HttpsPolicyFetcher implements MtaSts.Fetcher {
  static final int MAX_BYTES = 64 * 1024;

  private final DnsResolver resolver;
  private final HttpClient client;
  private final Duration timeout;

  HttpsPolicyFetcher(DnsResolver resolver, Duration timeout) {
    this.resolver = resolver;
    this.timeout = timeout;
    this.client =
        HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(timeout)
            .proxy(java.net.ProxySelector.of(null))
            .build();
  }

  @Override
  public String fetch(String domain) throws IOException {
    String host = "mta-sts." + domain;
    List<String> addresses;
    try {
      addresses = new java.util.ArrayList<>(resolver.lookup(host, DnsResolver.Type.A));
      addresses.addAll(resolver.lookup(host, DnsResolver.Type.AAAA));
    } catch (DnsResolver.DnsTemporaryException e) {
      throw new IOException("policy host lookup failed");
    }
    if (addresses.isEmpty()) {
      throw new IOException("policy host has no address");
    }
    for (String address : addresses) {
      if (!isPublic(InetAddress.getByName(address))) {
        throw new IOException("policy host is not a public address");
      }
    }
    HttpRequest request =
        HttpRequest.newBuilder(URI.create("https://" + host + "/.well-known/mta-sts.txt"))
            .timeout(timeout)
            .GET()
            .build();
    HttpResponse<InputStream> response;
    try {
      response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IOException("policy fetch interrupted");
    }
    try (InputStream body = response.body()) {
      if (response.statusCode() != 200) {
        throw new IOException("policy fetch status " + response.statusCode());
      }
      String type = response.headers().firstValue("content-type").orElse("");
      if (!type.toLowerCase(java.util.Locale.ROOT).startsWith("text/plain")) {
        throw new IOException("policy is not text/plain");
      }
      byte[] bytes = body.readNBytes(MAX_BYTES + 1);
      if (bytes.length > MAX_BYTES) {
        throw new IOException("policy too large");
      }
      return new String(bytes, StandardCharsets.UTF_8);
    }
  }

  /** Whether {@code address} is a globally routable unicast address. */
  static boolean isPublic(InetAddress address) {
    if (address.isAnyLocalAddress()
        || address.isLoopbackAddress()
        || address.isLinkLocalAddress()
        || address.isSiteLocalAddress()
        || address.isMulticastAddress()) {
      return false;
    }
    byte[] b = address.getAddress();
    if (b.length == 4) {
      int first = b[0] & 0xff;
      int second = b[1] & 0xff;
      return !(first == 0
          || (first == 100 && second >= 64 && second < 128)
          || (first == 192 && second == 0 && (b[2] & 0xff) == 0)
          || first >= 240);
    }
    return (b[0] & 0xfe) != 0xfc; // fc00::/7 unique local
  }
}
