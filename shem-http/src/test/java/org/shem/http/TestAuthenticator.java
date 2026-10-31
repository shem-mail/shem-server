package org.shem.http;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

/**
 * A minimal WebAuthn authenticator for tests: one P-256 credential, "none" attestation, user
 * presence only, and an incrementing signature counter. Builds the same CBOR and client data a
 * browser and security key would.
 */
final class TestAuthenticator {
  private static final ObjectMapper JSON = new ObjectMapper();
  private final KeyPair keys;
  private final byte[] credentialId = new byte[16];
  private final String origin;
  private final String rpId;
  int counter;

  TestAuthenticator(String origin, String rpId) throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec("secp256r1"));
    this.keys = generator.generateKeyPair();
    new java.security.SecureRandom().nextBytes(credentialId);
    this.origin = origin;
    this.rpId = rpId;
  }

  static String b64(byte[] bytes) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  String credentialId() {
    return b64(credentialId);
  }

  /** The body of {@code POST /me/mfa/webauthn} for a creation challenge. */
  ObjectNode register(String challenge, String label) throws Exception {
    byte[] clientData = clientData("webauthn.create", challenge);
    ByteArrayOutputStream auth = new ByteArrayOutputStream();
    auth.writeBytes(sha256(rpId.getBytes(StandardCharsets.UTF_8)));
    auth.write(0x41); // user present, attested credential data
    auth.writeBytes(ByteBuffer.allocate(4).putInt(counter).array());
    auth.writeBytes(new byte[16]); // AAGUID
    auth.write(0);
    auth.write(credentialId.length);
    auth.writeBytes(credentialId);
    auth.writeBytes(coseKey());
    byte[] authData = auth.toByteArray();
    ByteArrayOutputStream attestation = new ByteArrayOutputStream();
    attestation.write(0xa3);
    text(attestation, "fmt");
    text(attestation, "none");
    text(attestation, "attStmt");
    attestation.write(0xa0);
    text(attestation, "authData");
    attestation.write(0x59);
    attestation.write(authData.length >> 8);
    attestation.write(authData.length & 0xff);
    attestation.writeBytes(authData);
    return JSON.createObjectNode()
        .put("attestationObject", b64(attestation.toByteArray()))
        .put("clientDataJSON", b64(clientData))
        .put("label", label);
  }

  /** The {@code webauthn} object of {@code POST /auth/mfa/verify} for a request challenge. */
  ObjectNode assertion(String challenge) throws Exception {
    counter++;
    byte[] clientData = clientData("webauthn.get", challenge);
    ByteArrayOutputStream auth = new ByteArrayOutputStream();
    auth.writeBytes(sha256(rpId.getBytes(StandardCharsets.UTF_8)));
    auth.write(0x01);
    auth.writeBytes(ByteBuffer.allocate(4).putInt(counter).array());
    byte[] authData = auth.toByteArray();
    Signature signer = Signature.getInstance("SHA256withECDSA");
    signer.initSign(keys.getPrivate());
    signer.update(authData);
    signer.update(sha256(clientData));
    return JSON.createObjectNode()
        .put("credentialId", b64(credentialId))
        .put("authenticatorData", b64(authData))
        .put("clientDataJSON", b64(clientData))
        .put("signature", b64(signer.sign()));
  }

  private byte[] clientData(String type, String challenge) {
    return JSON.createObjectNode()
        .put("type", type)
        .put("challenge", challenge)
        .put("origin", origin)
        .put("crossOrigin", false)
        .toString()
        .getBytes(StandardCharsets.UTF_8);
  }

  private byte[] coseKey() {
    ECPublicKey key = (ECPublicKey) keys.getPublic();
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.write(0xa5);
    out.write(0x01); // kty
    out.write(0x02); // EC2
    out.write(0x03); // alg
    out.write(0x26); // -7 (ES256)
    out.write(0x20); // crv (-1)
    out.write(0x01); // P-256
    out.write(0x21); // x (-2)
    out.write(0x58);
    out.write(32);
    out.writeBytes(fixed(key.getW().getAffineX()));
    out.write(0x22); // y (-3)
    out.write(0x58);
    out.write(32);
    out.writeBytes(fixed(key.getW().getAffineY()));
    return out.toByteArray();
  }

  private static byte[] fixed(BigInteger value) {
    byte[] raw = value.toByteArray();
    byte[] out = new byte[32];
    int length = Math.min(raw.length, 32);
    System.arraycopy(raw, raw.length - length, out, 32 - length, length);
    return out;
  }

  private static void text(ByteArrayOutputStream out, String value) {
    byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
    out.write(0x60 + bytes.length);
    out.writeBytes(bytes);
  }

  private static byte[] sha256(byte[] data) throws Exception {
    return MessageDigest.getInstance("SHA-256").digest(data);
  }
}
