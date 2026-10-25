package org.shem.http;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.AttestedCredentialDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.credential.CredentialRecordImpl;
import com.webauthn4j.data.AuthenticationData;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.AuthenticationRequest;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.RegistrationRequest;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.attestation.statement.NoneAttestationStatement;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import org.jspecify.annotations.Nullable;
import org.shem.common.ImmutableBytes;

/**
 * WebAuthn ceremonies through webauthn4j. Attestation is not required ("none" is accepted): the
 * server trusts the authenticator a logged-in user registers, not a vendor chain. User presence is
 * required; user verification is preferred but not required, because the password was already
 * checked. Stored material is webauthn4j's serialized attested credential data (credential id and
 * public key).
 */
final class WebAuthn {
  static final List<PublicKeyCredentialParameters> ALGORITHMS =
      List.of(
          new PublicKeyCredentialParameters(
              PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256),
          new PublicKeyCredentialParameters(
              PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.EdDSA),
          new PublicKeyCredentialParameters(
              PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.RS256));

  /** A verified registration: the credential id, the material to store, and its counter. */
  record Registered(ImmutableBytes credentialId, ImmutableBytes material, long counter) {}

  private final WebAuthnManager manager;
  private final AttestedCredentialDataConverter converter;
  private final Origin origin;
  private final String rpId;

  WebAuthn(String origin) {
    ObjectConverter objects = new ObjectConverter();
    this.manager = WebAuthnManager.createNonStrictWebAuthnManager(objects);
    this.converter = new AttestedCredentialDataConverter(objects);
    this.origin = new Origin(origin);
    this.rpId = Objects.requireNonNull(URI.create(origin).getHost(), "origin needs a host");
  }

  String rpId() {
    return rpId;
  }

  /** Verifies a registration response; throws {@link IllegalArgumentException} if invalid. */
  Registered register(byte[] challenge, byte[] attestationObject, byte[] clientDataJson) {
    try {
      RegistrationData data =
          manager.verify(
              new RegistrationRequest(attestationObject, clientDataJson),
              new RegistrationParameters(
                  new ServerProperty(origin, rpId, new DefaultChallenge(challenge)),
                  ALGORITHMS,
                  false,
                  true));
      var authenticatorData =
          Objects.requireNonNull(data.getAttestationObject()).getAuthenticatorData();
      AttestedCredentialData credential =
          Objects.requireNonNull(authenticatorData.getAttestedCredentialData());
      return new Registered(
          ImmutableBytes.copyOf(credential.getCredentialId()),
          ImmutableBytes.copyOf(converter.convert(credential)),
          authenticatorData.getSignCount());
    } catch (RuntimeException e) {
      throw new IllegalArgumentException("invalid registration", e);
    }
  }

  byte[] credentialId(byte[] material) {
    return converter.extractCredentialId(material);
  }

  /**
   * Verifies an assertion against one stored credential; returns the new signature counter, or
   * {@code null} if the assertion is invalid.
   */
  @Nullable Long authenticate(
      byte[] challenge,
      byte[] material,
      long counter,
      byte[] credentialId,
      byte @Nullable [] userHandle,
      byte[] authenticatorData,
      byte[] clientDataJson,
      byte[] signature) {
    try {
      AttestedCredentialData credential = converter.convert(material);
      if (!Arrays.equals(credential.getCredentialId(), credentialId)) {
        return null;
      }
      CredentialRecordImpl record =
          new CredentialRecordImpl(
              new NoneAttestationStatement(),
              null,
              null,
              null,
              counter,
              credential,
              new com.webauthn4j.data.extension.authenticator
                  .AuthenticationExtensionsAuthenticatorOutputs<>(),
              null,
              null,
              null);
      AuthenticationData data =
          manager.verify(
              new AuthenticationRequest(
                  credentialId, userHandle, authenticatorData, clientDataJson, signature),
              new AuthenticationParameters(
                  new ServerProperty(origin, rpId, new DefaultChallenge(challenge)),
                  record,
                  List.of(credentialId),
                  false,
                  true));
      return Objects.requireNonNull(data.getAuthenticatorData()).getSignCount();
    } catch (RuntimeException e) {
      return null;
    }
  }
}
