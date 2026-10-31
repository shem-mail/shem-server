package org.shem.outbound;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import org.jspecify.annotations.Nullable;

/** A scriptable remote MX for outbound tests: records transactions, optional STARTTLS. */
final class FakeSmtpPeer implements AutoCloseable {
  /** One received transaction. */
  record Received(String from, List<String> to, String text, boolean tls) {}

  final List<Received> received = Collections.synchronizedList(new ArrayList<>());
  volatile Function<String, String> rcptReply = rcpt -> "250 2.1.5 OK";
  volatile String dataReply = "250 2.0.0 queued";
  final java.util.concurrent.atomic.AtomicInteger connections =
      new java.util.concurrent.atomic.AtomicInteger();
  private final ServerSocket server;
  private final @Nullable SSLContext tls;
  private final Thread acceptor;

  FakeSmtpPeer(@Nullable SSLContext tls) throws IOException {
    this.tls = tls;
    this.server = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
    this.acceptor = Thread.ofPlatform().daemon(true).start(this::acceptLoop);
  }

  int port() {
    return server.getLocalPort();
  }

  private void acceptLoop() {
    while (!server.isClosed()) {
      try {
        Socket socket = server.accept();
        connections.incrementAndGet();
        Thread.ofVirtual().start(() -> serve(socket));
      } catch (IOException e) {
        return;
      }
    }
  }

  private void serve(Socket socket) {
    try (Socket s = socket) {
      Socket current = s;
      InputStream in = new BufferedInputStream(current.getInputStream());
      OutputStream out = current.getOutputStream();
      write(out, "220 fake.test ESMTP");
      boolean secure = false;
      String from = "";
      List<String> to = new ArrayList<>();
      while (true) {
        String line = readLine(in);
        if (line == null) {
          return;
        }
        String upper = line.toUpperCase(java.util.Locale.ROOT);
        if (upper.startsWith("EHLO")) {
          write(
              out,
              tls != null && !secure
                  ? "250-fake.test\r\n250-8BITMIME\r\n250 STARTTLS"
                  : "250-fake.test\r\n250 8BITMIME");
        } else if (upper.startsWith("HELO")) {
          write(out, "250 fake.test");
        } else if (upper.equals("STARTTLS") && tls != null) {
          write(out, "220 2.0.0 ready");
          SSLSocket upgraded =
              (SSLSocket)
                  tls.getSocketFactory().createSocket(current, null, current.getPort(), true);
          upgraded.setUseClientMode(false);
          upgraded.startHandshake();
          current = upgraded;
          in = new BufferedInputStream(upgraded.getInputStream());
          out = upgraded.getOutputStream();
          secure = true;
        } else if (upper.startsWith("MAIL FROM:")) {
          from = line.substring(10).replace("<", "").replace(">", "");
          to = new ArrayList<>();
          write(out, "250 2.1.0 OK");
        } else if (upper.startsWith("RCPT TO:")) {
          String rcpt = line.substring(8).replace("<", "").replace(">", "");
          String reply = rcptReply.apply(rcpt);
          if (reply.startsWith("2")) {
            to.add(rcpt);
          }
          write(out, reply);
        } else if (upper.equals("DATA")) {
          write(out, "354 go ahead");
          ByteArrayOutputStream data = new ByteArrayOutputStream();
          while (true) {
            String body = readLine(in);
            if (body == null) {
              return;
            }
            if (body.equals(".")) {
              break;
            }
            data.writeBytes(
                ((body.startsWith("..") ? body.substring(1) : body) + "\r\n")
                    .getBytes(StandardCharsets.UTF_8));
          }
          if (dataReply.startsWith("2")) {
            received.add(
                new Received(from, List.copyOf(to), data.toString(StandardCharsets.UTF_8), secure));
          }
          write(out, dataReply);
        } else if (upper.equals("QUIT")) {
          write(out, "221 bye");
          return;
        } else {
          write(out, "500 unknown");
        }
      }
    } catch (IOException e) {
      // client went away
    }
  }

  private static void write(OutputStream out, String reply) throws IOException {
    out.write((reply + "\r\n").getBytes(StandardCharsets.US_ASCII));
    out.flush();
  }

  private static @Nullable String readLine(InputStream in) throws IOException {
    ByteArrayOutputStream line = new ByteArrayOutputStream();
    int b;
    while ((b = in.read()) != -1) {
      if (b == '\n') {
        String text = line.toString(StandardCharsets.UTF_8);
        return text.endsWith("\r") ? text.substring(0, text.length() - 1) : text;
      }
      line.write(b);
    }
    return null;
  }

  @Override
  public void close() throws IOException {
    server.close();
    acceptor.interrupt();
  }
}
