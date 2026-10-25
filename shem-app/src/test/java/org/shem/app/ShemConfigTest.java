package org.shem.app;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Path;
import java.util.Properties;
import org.junit.jupiter.api.Test;

class ShemConfigTest {
  private static final Path BASE = Path.of("/srv/shem");

  private static Properties base() {
    Properties p = new Properties();
    p.setProperty("data.directory", "data");
    return p;
  }

  private static Properties withTls() {
    Properties p = base();
    p.setProperty("tls.certificateChain", "tls/chain.pem");
    p.setProperty("tls.privateKey", "tls/key.pem");
    p.setProperty("tls.hostNames", "mail.example.org");
    return p;
  }

  @Test
  void smtpListenerUsesDefaultsAndRequiresTls() {
    Properties p = withTls();
    p.setProperty("smtp.bind", "0.0.0.0:25");
    ShemConfig.Smtp smtp =
        java.util.Objects.requireNonNull(ShemConfig.fromProperties(p, BASE).smtp());
    assertThat(smtp.bind().getPort()).isEqualTo(25);
    assertThat(smtp.maxRecipients()).isEqualTo(100);
    assertThat(smtp.maxUnknownRecipients()).isEqualTo(5);

    Properties noTls = base();
    noTls.setProperty("smtp.bind", "0.0.0.0:25");
    assertThatThrownBy(() -> ShemConfig.fromProperties(noTls, BASE))
        .hasMessageContaining("smtp requires tls");
  }

  @Test
  void invalidSmtpLimitsAndUnknownKeysFailStartup() {
    Properties p = withTls();
    p.setProperty("smtp.bind", "0.0.0.0:25");
    p.setProperty("smtp.maxRecipients", "0");
    assertThatThrownBy(() -> ShemConfig.fromProperties(p, BASE))
        .hasMessageContaining("smtp limits");
    Properties unknown = withTls();
    unknown.setProperty("smtp.relay", "true");
    assertThatThrownBy(() -> ShemConfig.fromProperties(unknown, BASE))
        .hasMessageContaining("unknown configuration keys");
  }

  @Test
  void listenersAreOptional() {
    ShemConfig config = ShemConfig.fromProperties(base(), BASE);
    assertThat(config.imap()).isNull();
    assertThat(config.smtp()).isNull();
    assertThat(config.dataDirectory()).isEqualTo(Path.of("/srv/shem/data"));
  }
}
