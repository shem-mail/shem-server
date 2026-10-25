package org.shem.smtp;

import java.util.Optional;
import java.util.Set;
import org.apache.james.jwt.OidcSASLConfiguration;
import org.apache.james.protocols.smtp.SMTPConfiguration;

/** Fixed inbound configuration: never relays, never offers AUTH, enforces HELO and brackets. */
final class ShemSmtpConfiguration implements SMTPConfiguration {
  private final InboundSettings settings;

  ShemSmtpConfiguration(InboundSettings settings) {
    this.settings = settings;
  }

  @Override
  public String getHelloName() {
    return settings.hostName();
  }

  @Override
  public String getSoftwareName() {
    return "Shem";
  }

  @Override
  public String getGreeting() {
    return settings.hostName() + " ESMTP";
  }

  @Override
  public long getMaxMessageSize() {
    return settings.maxMessageBytes();
  }

  @Override
  public boolean isRelayingAllowed(String remoteIP) {
    return false;
  }

  @Override
  public boolean isAuthAnnounced(String remoteIP, boolean tlsStarted) {
    return false;
  }

  @Override
  public SenderVerificationConfiguration senderVerificationConfiguration() {
    return new SenderVerificationConfiguration(SenderVerificationMode.DISABLED, true);
  }

  @Override
  public boolean useHeloEhloEnforcement() {
    return true;
  }

  @Override
  public boolean useAddressBracketsEnforcement() {
    return true;
  }

  @Override
  public boolean isPlainAuthEnabled() {
    return false;
  }

  @Override
  public Optional<OidcSASLConfiguration> saslConfiguration() {
    return Optional.empty();
  }

  @Override
  public Set<String> disabledFeatures() {
    return Set.of();
  }
}
