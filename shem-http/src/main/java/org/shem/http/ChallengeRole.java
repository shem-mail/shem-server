package org.shem.http;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import org.jspecify.annotations.Nullable;
import org.shem.tls.Http01Challenges;

/**
 * The plain-HTTP listener (port 80, ADR 0018). It serves exactly two things: active ACME HTTP-01
 * tokens, and permanent redirects to HTTPS on a configured host. There is no authentication and no
 * API here. Redirect targets are built from the configured host list; the request's Host header
 * only selects among those names and never flows into the Location header otherwise.
 */
public final class ChallengeRole implements AutoCloseable {
  static final int MAX_PATH = 2048;

  private final HttpServer server;
  private final ThreadPoolExecutor executor;

  private ChallengeRole(HttpServer server, ThreadPoolExecutor executor) {
    this.server = server;
    this.executor = executor;
  }

  public static ChallengeRole start(
      InetSocketAddress bind, Http01Challenges challenges, List<String> hosts) throws IOException {
    if (hosts.isEmpty()) {
      throw new IllegalArgumentException("at least one host is required for redirects");
    }
    List<String> allowed = hosts.stream().map(h -> h.toLowerCase(Locale.ROOT)).toList();
    HttpServer server = HttpServer.create(bind, 64);
    server.createContext("/", exchange -> handle(exchange, challenges, allowed));
    ThreadPoolExecutor executor =
        new ThreadPoolExecutor(
            4,
            4,
            30,
            TimeUnit.SECONDS,
            new ArrayBlockingQueue<>(64),
            Thread.ofVirtual().name("shem-http80-", 0).factory(),
            new ThreadPoolExecutor.DiscardPolicy());
    server.setExecutor(executor);
    server.start();
    return new ChallengeRole(server, executor);
  }

  public int port() {
    return server.getAddress().getPort();
  }

  private static void handle(HttpExchange exchange, Http01Challenges challenges, List<String> hosts)
      throws IOException {
    try (exchange) {
      exchange.getResponseHeaders().set("Cache-Control", "no-store");
      exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
      String method = exchange.getRequestMethod();
      boolean head = method.equals("HEAD");
      if (!head && !method.equals("GET")) {
        exchange.getResponseHeaders().set("Allow", "GET, HEAD");
        exchange.sendResponseHeaders(405, -1);
        return;
      }
      String path = exchange.getRequestURI().getRawPath();
      if (path != null && path.startsWith(Http01Challenges.PATH_PREFIX)) {
        Optional<String> answer =
            challenges.lookup(path.substring(Http01Challenges.PATH_PREFIX.length()));
        if (answer.isEmpty()) {
          exchange.sendResponseHeaders(404, -1);
          return;
        }
        byte[] body = answer.get().getBytes(StandardCharsets.US_ASCII);
        exchange.getResponseHeaders().set("Content-Type", "text/plain");
        exchange.sendResponseHeaders(200, head ? -1 : body.length);
        if (!head) {
          try (OutputStream out = exchange.getResponseBody()) {
            out.write(body);
          }
        }
        return;
      }
      exchange
          .getResponseHeaders()
          .set("Location", redirect(exchange.getRequestHeaders().getFirst("Host"), path, hosts));
      exchange.sendResponseHeaders(301, -1);
    }
  }

  /** {@code https://} plus a configured host plus the path if it is safe, else {@code /}. */
  static String redirect(
      @Nullable String hostHeader, @Nullable String rawPath, List<String> hosts) {
    String host = hosts.get(0);
    if (hostHeader != null) {
      String requested = hostHeader.strip().toLowerCase(Locale.ROOT);
      int colon = requested.lastIndexOf(':');
      if (colon > 0 && requested.indexOf(']') < colon) {
        requested = requested.substring(0, colon);
      }
      if (hosts.contains(requested)) {
        host = requested;
      }
    }
    boolean safe =
        rawPath != null
            && rawPath.startsWith("/")
            && !rawPath.startsWith("//")
            && rawPath.length() <= MAX_PATH
            && rawPath.chars().allMatch(c -> c > 0x20 && c < 0x7f && c != '\\');
    return "https://" + host + (safe ? rawPath : "/");
  }

  @Override
  public void close() {
    server.stop(0);
    executor.shutdownNow();
  }
}
