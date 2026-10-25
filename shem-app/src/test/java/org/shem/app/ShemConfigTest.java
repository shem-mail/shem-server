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

  @Test
  void policyDefaultsAndValidation() {
    ShemConfig.Policy policy = ShemConfig.fromProperties(base(), BASE).policy();
    assertThat(policy.junkScore()).isEqualTo(5.0);
    assertThat(policy.dmarcReject()).isEqualTo(org.shem.policy.InboundPolicy.Enforcement.REJECT);
    assertThat(policy.greylist()).isTrue();
    assertThat(policy.blocklists()).isEmpty();
    assertThat(policy.rulesFile()).isNull();

    Properties p = base();
    p.setProperty("policy.dangerousAttachments", "junk");
    p.setProperty("policy.rulesFile", "rules/local.rules");
    p.setProperty("policy.blocklists", "zen.example, ,bl.example");
    ShemConfig.Policy custom = ShemConfig.fromProperties(p, BASE).policy();
    assertThat(custom.dangerousAttachments())
        .isEqualTo(org.shem.policy.InboundPolicy.Enforcement.JUNK);
    assertThat(custom.rulesFile()).isEqualTo(Path.of("/srv/shem/rules/local.rules"));
    assertThat(custom.blocklists()).containsExactly("zen.example", "bl.example");

    Properties bad = base();
    bad.setProperty("policy.dmarcReject", "ignore");
    assertThatThrownBy(() -> ShemConfig.fromProperties(bad, BASE))
        .hasMessageContaining("policy.dmarcReject");
  }

  @Test
  void submissionListenersRequireTls() {
    Properties p = withTls();
    p.setProperty("submission.startTlsBind", "0.0.0.0:587");
    ShemConfig.Submission submission =
        java.util.Objects.requireNonNull(ShemConfig.fromProperties(p, BASE).submission());
    assertThat(submission.implicitTlsBind()).isNull();
    assertThat(java.util.Objects.requireNonNull(submission.startTlsBind()).getPort())
        .isEqualTo(587);
    assertThat(submission.recipientsPerHour()).isEqualTo(500);
    Properties noTls = base();
    noTls.setProperty("submission.implicitTlsBind", "0.0.0.0:465");
    assertThatThrownBy(() -> ShemConfig.fromProperties(noTls, BASE))
        .hasMessageContaining("submission requires tls");
  }
}
