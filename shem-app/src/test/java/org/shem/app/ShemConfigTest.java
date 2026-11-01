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

  @Test
  void outboundRequiresSubmissionAndDefaultsAreBounded() {
    Properties p = withTls();
    p.setProperty("submission.startTlsBind", "0.0.0.0:587");
    p.setProperty("outbound.enabled", "true");
    ShemConfig.Outbound outbound =
        java.util.Objects.requireNonNull(ShemConfig.fromProperties(p, BASE).outbound());
    assertThat(outbound.lifetime()).isEqualTo(java.time.Duration.ofDays(5));
    assertThat(outbound.maxItems()).isEqualTo(10_000);
    Properties alone = withTls();
    alone.setProperty("outbound.enabled", "true");
    assertThatThrownBy(() -> ShemConfig.fromProperties(alone, BASE))
        .hasMessageContaining("requires a submission listener");
    assertThat(ShemConfig.fromProperties(withTls(), BASE).outbound()).isNull();
  }

  @Test
  void httpListenerRequiresTlsAndHasBoundedSessionDefaults() {
    Properties p = withTls();
    p.setProperty("http.bind", "0.0.0.0:443");
    ShemConfig.Http http =
        java.util.Objects.requireNonNull(ShemConfig.fromProperties(p, BASE).http());
    assertThat(http.idleTimeout()).isEqualTo(java.time.Duration.ofMinutes(30));
    assertThat(http.absoluteLifetime()).isEqualTo(java.time.Duration.ofHours(12));
    Properties noTls = base();
    noTls.setProperty("http.bind", "127.0.0.1:8443");
    assertThatThrownBy(() -> ShemConfig.fromProperties(noTls, BASE))
        .hasMessageContaining("http requires tls");
    Properties removed = withTls();
    removed.setProperty("http.allowWithoutMfa", "true");
    assertThatThrownBy(() -> ShemConfig.fromProperties(removed, BASE))
        .as("MFA is mandatory; the opt-out no longer exists")
        .hasMessageContaining("unknown configuration keys");
  }

  private static Properties withAcme() {
    Properties p = base();
    p.setProperty("tls.hostNames", "Mail.Example.org, mta-sts.example.org");
    p.setProperty("acme.directory", "https://acme-staging-v02.api.letsencrypt.org/directory");
    p.setProperty("acme.agreeToTerms", "true");
    p.setProperty("acme.challengeBind", "0.0.0.0:80");
    return p;
  }

  @Test
  void acmeManagesTheCertificateFilesUnderTheDataDirectory() {
    ShemConfig.Tls tls =
        java.util.Objects.requireNonNull(ShemConfig.fromProperties(withAcme(), BASE).tls());
    assertThat(tls.certificateChain()).isEqualTo(Path.of("/srv/shem/data/acme/live/chain.pem"));
    assertThat(tls.privateKey()).isEqualTo(Path.of("/srv/shem/data/acme/live/key.pem"));
    assertThat(tls.hostNames()).containsExactly("mail.example.org", "mta-sts.example.org");
    ShemConfig.Acme acme = java.util.Objects.requireNonNull(tls.acme());
    assertThat(acme.challengeBind().getPort()).isEqualTo(80);
    assertThat(acme.email()).isNull();
  }

  @Test
  void acmeNeedsExplicitTermsAcceptanceAHttpsDirectoryAndNoManualFiles() {
    Properties noTerms = withAcme();
    noTerms.remove("acme.agreeToTerms");
    assertThatThrownBy(() -> ShemConfig.fromProperties(noTerms, BASE))
        .hasMessageContaining("acme.agreeToTerms");
    Properties plain = withAcme();
    plain.setProperty("acme.directory", "http://acme.example/directory");
    assertThatThrownBy(() -> ShemConfig.fromProperties(plain, BASE)).hasMessageContaining("https");
    Properties both = withAcme();
    both.setProperty("tls.certificateChain", "x.pem");
    assertThatThrownBy(() -> ShemConfig.fromProperties(both, BASE))
        .hasMessageContaining("remove tls.certificateChain");
    Properties noBind = withAcme();
    noBind.remove("acme.challengeBind");
    assertThatThrownBy(() -> ShemConfig.fromProperties(noBind, BASE))
        .hasMessageContaining("acme.challengeBind");
  }

  @Test
  void mtaStsNeedsTheHttpsListenerAndAKnownMode() {
    Properties p = withTls();
    p.setProperty("mtaSts.mode", "Enforce");
    assertThatThrownBy(() -> ShemConfig.fromProperties(p, BASE)).hasMessageContaining("http.bind");
    p.setProperty("http.bind", "0.0.0.0:443");
    ShemConfig.MtaSts mtaSts =
        java.util.Objects.requireNonNull(ShemConfig.fromProperties(p, BASE).mtaSts());
    assertThat(mtaSts.mode()).isEqualTo("enforce");
    assertThat(mtaSts.maxAge()).isEqualTo(java.time.Duration.ofDays(7));
    p.setProperty("mtaSts.mode", "strict");
    assertThatThrownBy(() -> ShemConfig.fromProperties(p, BASE))
        .hasMessageContaining("mtaSts.mode");
  }

  @Test
  void extractionRequiresScratchAndIsolationInProduction() {
    Properties p = base();
    p.setProperty("extraction.enabled", "true");
    assertThatThrownBy(() -> ShemConfig.fromProperties(p, BASE))
        .hasMessageContaining("extraction.scratch");
    p.setProperty("extraction.scratch", "/dev/shm/shem");
    p.setProperty("extraction.sandbox", "bin/sandbox");
    ShemConfig.Extraction extraction =
        java.util.Objects.requireNonNull(ShemConfig.fromProperties(p, BASE).extraction());
    assertThat(extraction.requireIsolation()).isTrue();
    assertThat(extraction.sandbox()).isEqualTo(Path.of("/srv/shem/bin/sandbox"));
    assertThat(extraction.workers()).isEqualTo(2);
    p.setProperty("extraction.requireIsolation", "false");
    assertThatThrownBy(() -> ShemConfig.fromProperties(p, BASE))
        .hasMessageContaining("only allowed in development mode");
    p.setProperty("mode", "development");
    assertThat(ShemConfig.fromProperties(p, BASE).extraction()).isNotNull();
  }

  @Test
  void bootstrapDefaultsAndValidation() {
    ShemConfig.Bootstrap defaults = ShemConfig.fromProperties(base(), BASE).bootstrap();
    assertThat(defaults.enabled()).isTrue();
    assertThat(defaults.adminName()).isEqualTo("admin");
    assertThat(defaults.adminPasswordFile()).isNull();
    assertThat(defaults.domain()).isNull();
    assertThat(defaults.validity()).isEqualTo(java.time.Duration.ofDays(3));

    Properties p = base();
    p.setProperty("bootstrap.adminPasswordFile", "secrets/admin");
    p.setProperty("bootstrap.domain", "Example.ORG.");
    ShemConfig.Bootstrap set = ShemConfig.fromProperties(p, BASE).bootstrap();
    assertThat(set.adminPasswordFile()).isEqualTo(Path.of("/srv/shem/secrets/admin"));
    assertThat(set.domain()).isEqualTo("example.org");

    Properties badName = base();
    badName.setProperty("bootstrap.adminName", "Root User");
    assertThatThrownBy(() -> ShemConfig.fromProperties(badName, BASE))
        .hasMessageContaining("bootstrap.adminName");
    Properties badDomain = base();
    badDomain.setProperty("bootstrap.domain", "not a domain");
    assertThatThrownBy(() -> ShemConfig.fromProperties(badDomain, BASE))
        .hasMessageContaining("bootstrap.domain");
    Properties badValidity = base();
    badValidity.setProperty("bootstrap.validity", "P90D");
    assertThatThrownBy(() -> ShemConfig.fromProperties(badValidity, BASE))
        .hasMessageContaining("bootstrap.validity");
  }

  @Test
  void documentedDockerExampleIsAValidConfiguration() throws Exception {
    ShemConfig config = ShemConfig.load(Path.of("../docs/examples/shem.properties"));
    assertThat(config.dataDirectory()).isEqualTo(Path.of("/data"));
    assertThat(config.bootstrap().adminPasswordFile())
        .isEqualTo(Path.of("/run/secrets/shem_admin_password"));
    assertThat(config.bootstrap().domain()).isEqualTo("example.org");
    assertThat(config.http()).isNotNull();
    assertThat(java.util.Objects.requireNonNull(config.tls()).acme()).isNotNull();
  }
}
