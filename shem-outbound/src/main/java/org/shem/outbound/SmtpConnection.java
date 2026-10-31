package org.shem.outbound;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;

/**
 * A minimal blocking SMTP client connection for relaying (RFC 5321) with STARTTLS (RFC 3207). It
 * reads bounded replies, streams DATA with dot-stuffing and CRLF normalization of line ends, and
 * never logs or retains transcripts.
 */
final class SmtpConnection implements AutoCloseable {
  static final int MAX_REPLY_LINES = 100;
  static final int MAX_LINE = 4096;

  /** One SMTP reply: code and the text of the last line. */
  record Reply(int code, List<String> lines) {
    boolean positive() {
      return code >= 200 && code < 400;
    }

    boolean permanent() {
      return code >= 500;
    }

    /** Reply code with the enhanced status code when present, e.g. {@code "550 5.1.1"}. */
    String summary() {
      String text = lines.isEmpty() ? "" : lines.getLast();
      if (text.matches("[245]\\.\\d{1,3}\\.\\d{1,3}( .*)?")) {
        return code
            + " "
            + text.substring(0, text.indexOf(' ') < 0 ? text.length() : text.indexOf(' '));
      }
      return String.valueOf(code);
    }
  }

  private Socket socket;
  private InputStream in;
  private OutputStream out;
  private final Duration commandTimeout;

  private SmtpConnection(Socket socket, Duration commandTimeout) throws IOException {
    this.socket = socket;
    this.commandTimeout = commandTimeout;
    socket.setSoTimeout((int) commandTimeout.toMillis());
    this.in = new BufferedInputStream(socket.getInputStream());
    this.out = new BufferedOutputStream(socket.getOutputStream());
  }

  static SmtpConnection open(
      String host, int port, Duration connectTimeout, Duration commandTimeout) throws IOException {
    Socket socket = new Socket(java.net.Proxy.NO_PROXY);
    try {
      socket.connect(new InetSocketAddress(host, port), (int) connectTimeout.toMillis());
      return new SmtpConnection(socket, commandTimeout);
    } catch (IOException | RuntimeException e) {
      socket.close();
      throw e;
    }
  }

  Reply read() throws IOException {
    List<String> lines = new ArrayList<>();
    int code = -1;
    while (true) {
      String line = readLine();
      if (line.length() < 3) {
        throw new IOException("malformed reply");
      }
      int lineCode;
      try {
        lineCode = Integer.parseInt(line.substring(0, 3));
      } catch (NumberFormatException e) {
        throw new IOException("malformed reply");
      }
      if (code != -1 && lineCode != code) {
        throw new IOException("inconsistent reply");
      }
      code = lineCode;
      lines.add(line.length() > 4 ? line.substring(4) : "");
      if (lines.size() > MAX_REPLY_LINES) {
        throw new IOException("reply too long");
      }
      if (line.length() == 3 || line.charAt(3) == ' ') {
        return new Reply(code, List.copyOf(lines));
      }
      if (line.charAt(3) != '-') {
        throw new IOException("malformed reply");
      }
    }
  }

  Reply command(String command) throws IOException {
    out.write((command + "\r\n").getBytes(StandardCharsets.US_ASCII));
    out.flush();
    return read();
  }

  /** EHLO, falling back to HELO; returns the upper-case extension keywords (empty after HELO). */
  Set<String> hello(String name) throws IOException {
    Reply ehlo = command("EHLO " + name);
    if (ehlo.positive()) {
      Set<String> extensions = new HashSet<>();
      for (String line : ehlo.lines().subList(1, ehlo.lines().size())) {
        extensions.add(line.split(" ", 2)[0].toUpperCase(Locale.ROOT));
      }
      return extensions;
    }
    Reply helo = command("HELO " + name);
    if (!helo.positive()) {
      throw new IOException("HELO refused");
    }
    return Set.of();
  }

  /**
   * Upgrades with STARTTLS. With {@code verifyHost} non-null the certificate chain is validated by
   * {@code context}'s trust managers and must match that host name.
   */
  void startTls(SSLContext context, String sniHost, boolean verifyHost) throws IOException {
    Reply reply = command("STARTTLS");
    if (reply.code() != 220) {
      throw new IOException("STARTTLS refused");
    }
    SSLSocket tls =
        (SSLSocket)
            context.getSocketFactory().createSocket(socket, sniHost, socket.getPort(), true);
    SSLParameters parameters = tls.getSSLParameters();
    parameters.setProtocols(new String[] {"TLSv1.3", "TLSv1.2"});
    try {
      parameters.setServerNames(List.of(new SNIHostName(sniHost)));
    } catch (IllegalArgumentException e) {
      // An address literal cannot be sent as SNI.
    }
    if (verifyHost) {
      parameters.setEndpointIdentificationAlgorithm("HTTPS");
    }
    tls.setSSLParameters(parameters);
    tls.setSoTimeout((int) commandTimeout.toMillis());
    tls.startHandshake();
    socket = tls;
    in = new BufferedInputStream(tls.getInputStream());
    out = new BufferedOutputStream(tls.getOutputStream());
  }

  boolean tlsActive() {
    return socket instanceof SSLSocket;
  }

  /** Sends the message body after a 354 reply, then reads the final reply. */
  Reply data(InputStream message, Duration dataTimeout) throws IOException {
    socket.setSoTimeout((int) dataTimeout.toMillis());
    boolean lineStart = true;
    int previous = -1;
    byte[] buffer = new byte[8192];
    int n;
    while ((n = message.read(buffer)) > 0) {
      for (int i = 0; i < n; i++) {
        int b = buffer[i] & 0xff;
        if (b == '\n' && previous != '\r') {
          out.write('\r');
        }
        if (lineStart && b == '.') {
          out.write('.');
        }
        out.write(b);
        lineStart = b == '\n';
        previous = b;
      }
    }
    if (!lineStart) {
      out.write('\r');
      out.write('\n');
    }
    out.write(".\r\n".getBytes(StandardCharsets.US_ASCII));
    out.flush();
    Reply reply = read();
    socket.setSoTimeout((int) commandTimeout.toMillis());
    return reply;
  }

  private String readLine() throws IOException {
    ByteArrayOutputStream line = new ByteArrayOutputStream();
    int b;
    while ((b = in.read()) != -1) {
      if (b == '\n') {
        String text = line.toString(StandardCharsets.UTF_8);
        return text.endsWith("\r") ? text.substring(0, text.length() - 1) : text;
      }
      if (line.size() >= MAX_LINE) {
        throw new IOException("reply line too long");
      }
      line.write(b);
    }
    throw new IOException("connection closed");
  }

  @Override
  public void close() {
    try {
      out.write("QUIT\r\n".getBytes(StandardCharsets.US_ASCII));
      out.flush();
    } catch (IOException e) {
      // The peer may already have closed the connection.
    }
    try {
      socket.close();
    } catch (IOException e) {
      // Nothing left to release.
    }
  }
}
