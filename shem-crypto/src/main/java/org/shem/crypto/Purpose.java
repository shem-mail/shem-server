package org.shem.crypto;

/**
 * Domain-separation labels. Every key derivation and every associated-data block carries exactly
 * one purpose, so ciphertext produced for one purpose cannot be substituted for another.
 */
public enum Purpose {
  CREDENTIAL_SLOT("slot"),
  KEYRING("keyring"),
  CONTENT_KEY_ENVELOPE("content-key-envelope"),
  CONTENT_KEY_WRAP("content-key-wrap"),
  MESSAGE_BLOB("message-blob"),
  DELIVERY_RECEIPT("delivery-receipt"),
  METADATA_JOURNAL("metadata-journal"),
  METADATA_SNAPSHOT("metadata-snapshot"),
  METADATA_MANIFEST("metadata-manifest"),
  SEARCH_INDEX("search-index"),
  EXPORT("export"),
  POLICY_FINGERPRINT("policy-fingerprint");

  private final String label;

  Purpose(String label) {
    this.label = label;
  }

  public String label() {
    return label;
  }
}
