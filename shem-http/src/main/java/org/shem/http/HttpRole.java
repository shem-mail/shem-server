package org.shem.http;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLParameters;
import org.shem.identity.IdentityService;
import org.shem.mailbox.KeyLifecycle;
import org.shem.mailbox.SessionService;
import org.shem.tls.ReloadableTlsContext;

/**
 * The HTTPS listener (JDK {@code com.sun.net.httpserver}, no web framework). TLS 1.2+ only, from
 * the reloadable listener certificate. Requests run on a bounded pool of virtual threads; when it
 * is saturated the connection is refused rather than queued without limit.
 */
public final class HttpRole implements AutoCloseable {
  private final HttpsServer server;
  private final ThreadPoolExecutor executor;
  private final ScheduledExecutorService sweeper;
  private final SessionStore sessions;

  private HttpRole(
      HttpsServer server,
      ThreadPoolExecutor executor,
      ScheduledExecutorService sweeper,
      SessionStore sessions) {
    this.server = server;
    this.executor = executor;
    this.sweeper = sweeper;
    this.sessions = sessions;
  }

  public static HttpRole start(
      HttpSettings settings,
      SessionService auth,
      KeyLifecycle lifecycle,
      IdentityService identity,
      ReloadableTlsContext tls,
      SecureRandom random,
      Clock clock)
      throws java.io.IOException {
    SessionStore sessions = new SessionStore(settings, clock, random);
    HttpsServer server = HttpsServer.create(settings.bind(), 128);
    server.setHttpsConfigurator(
        new HttpsConfigurator(tls.sslContext()) {
          @Override
          public void configure(HttpsParameters params) {
            SSLParameters parameters = getSSLContext().getDefaultSSLParameters();
            parameters.setProtocols(new String[] {"TLSv1.3", "TLSv1.2"});
            params.setSSLParameters(parameters);
          }
        });
    server.createContext("/", new Api(settings, sessions, auth, lifecycle, identity, clock));
    ThreadPoolExecutor executor =
        new ThreadPoolExecutor(
            settings.maxConcurrentRequests(),
            settings.maxConcurrentRequests(),
            30,
            TimeUnit.SECONDS,
            new ArrayBlockingQueue<>(settings.maxConcurrentRequests() * 4),
            Thread.ofVirtual().name("shem-http-", 0).factory());
    server.setExecutor(executor);
    ScheduledExecutorService sweeper =
        Executors.newSingleThreadScheduledExecutor(
            Thread.ofPlatform().name("shem-http-sweeper").daemon(true).factory());
    var unused = sweeper.scheduleWithFixedDelay(sessions::sweep, 30, 30, TimeUnit.SECONDS);
    server.start();
    return new HttpRole(server, executor, sweeper, sessions);
  }

  public int port() {
    return server.getAddress().getPort();
  }

  int sessionCount() {
    return sessions.size();
  }

  @Override
  public void close() {
    server.stop(1);
    sweeper.shutdownNow();
    executor.shutdownNow();
    sessions.close();
  }
}
