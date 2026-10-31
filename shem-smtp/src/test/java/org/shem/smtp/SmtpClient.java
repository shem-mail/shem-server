package org.shem.smtp;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import org.jspecify.annotations.Nullable;

/** Minimal blocking SMTP client for black-box tests; responses are returned as raw lines. */
final class SmtpClient implements AutoCloseable {
  private final SSLContext trust;
  private Socket socket;
  private InputStream in;
  private OutputStream out;

  SmtpClient(int port, SSLContext trust) throws IOException {
    this.trust = trust;
    this.socket = new Socket(InetAddress.getLoopbackAddress(), port);
    socket.setSoTimeout(15_000);
    this.in = new BufferedInputStream(socket.getInputStream());
    this.out = socket.getOutputStream();
  }

  /** Reads one (possibly multi-line) reply; returns an empty list on EOF. */
  List<String> reply() throws IOException {
    List<String> lines = new ArrayList<>();
    while (true) {
      String line = readLine();
      if (line == null) {
        return lines;
      }
      lines.add(line);
      if (line.length() < 4 || line.charAt(3) != '-') {
        return lines;
      }
    }
  }

  /** The final line of the next reply, or {@code "EOF"}. */
  String last() throws IOException {
    List<String> lines = reply();
    return lines.isEmpty() ? "EOF" : lines.getLast();
  }

  String command(String command) throws IOException {
    send(command + "\r\n");
    return last();
  }

  void send(String raw) throws IOException {
    write(raw.getBytes(StandardCharsets.UTF_8));
  }

  void write(byte[] bytes) throws IOException {
    out.write(bytes);
    out.flush();
  }

  void startTls() throws IOException {
    SSLSocket tls =
        (SSLSocket)
            trust.getSocketFactory().createSocket(socket, SmtpFixture.HOST, socket.getPort(), true);
    tls.startHandshake();
    socket = tls;
    in = new BufferedInputStream(tls.getInputStream());
    out = tls.getOutputStream();
  }

  /** Runs one transaction; returns the final DATA reply (or the first failing reply). */
  String send(String from, List<String> to, String message) throws IOException {
    String reply = command("MAIL FROM:<" + from + ">");
    if (!reply.startsWith("250")) {
      return reply;
    }
    for (String rcpt : to) {
      reply = command("RCPT TO:<" + rcpt + ">");
      if (!reply.startsWith("250")) {
        return reply;
      }
    }
    reply = command("DATA");
    if (!reply.startsWith("354")) {
      return reply;
    }
    send(message.replace("\r\n.", "\r\n.."));
    return command((message.endsWith("\r\n") ? "" : "\r\n") + ".");
  }

  private @Nullable String readLine() throws IOException {
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
    socket.close();
  }
}
