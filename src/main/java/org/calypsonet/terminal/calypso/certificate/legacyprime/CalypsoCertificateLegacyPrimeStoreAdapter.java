/* **************************************************************************************
 * Copyright (c) 2025 Calypso Networks Association https://calypsonet.org/
 *
 * See the NOTICE file(s) distributed with this work for additional information
 * regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the terms of the
 * Eclipse Public License 2.0 which is available at http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 ************************************************************************************** */
package org.calypsonet.terminal.calypso.certificate.legacyprime;

import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.HexUtil;

/**
 * Adapter implementation of {@link CalypsoCertificateLegacyPrimeStore}.
 *
 * <p>This class manages the storage of Calypso Prime Legacy Certificate Authority (CA) certificates
 * and public keys, maintaining the chain of trust for certificate operations.
 *
 * @since 0.1.0
 */
final class CalypsoCertificateLegacyPrimeStoreAdapter
    implements CalypsoCertificateLegacyPrimeStore {

  private final Map<String, RSAPublicKey> pcaPublicKeys;
  private final Map<String, CaCertificate> caCertificates;

  /**
   * Creates a new instance of the store.
   *
   * @since 0.1.0
   */
  CalypsoCertificateLegacyPrimeStoreAdapter() {
    this.pcaPublicKeys = new HashMap<>();
    this.caCertificates = new HashMap<>();
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public void addPcaPublicKey(byte[] pcaPublicKeyReference, RSAPublicKey pcaPublicKey) {
    Assert.getInstance()
        .notNull(pcaPublicKeyReference, "pcaPublicKeyReference")
        .notNull(pcaPublicKey, "pcaPublicKey")
        .isEqual(pcaPublicKey.getModulus().bitLength(), 2048, "PCA public key modulus bit length")
        .isEqual(pcaPublicKey.getPublicExponent().intValue(), 65537, "PCA public key exponent");

    String keyRef = HexUtil.toHex(pcaPublicKeyReference);
    checkKeyRefNotExists(keyRef);

    pcaPublicKeys.put(keyRef, pcaPublicKey);
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public void addPcaPublicKey(byte[] pcaPublicKeyReference, byte[] pcaPublicKeyModulus) {
    Assert.getInstance()
        .notNull(pcaPublicKeyReference, "pcaPublicKeyReference")
        .notNull(pcaPublicKeyModulus, "pcaPublicKeyModulus")
        .isEqual(pcaPublicKeyModulus.length, 256, "pcaPublicKeyModulus length");

    String keyRef = HexUtil.toHex(pcaPublicKeyReference);
    checkKeyRefNotExists(keyRef);

    RSAPublicKey publicKey = CertificateUtils.generateRSAPublicKeyFromModulus(pcaPublicKeyModulus);
    pcaPublicKeys.put(keyRef, publicKey);
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public byte[] addCalypsoCaCertificateLegacyPrime(byte[] caCertificate) {
    Assert.getInstance()
        .notNull(caCertificate, "caCertificate")
        .isEqual(caCertificate.length, 384, "caCertificate length");

    // Parse the CA certificate
    CaCertificate certificate = CaCertificate.fromBytes(caCertificate);

    // Verify certificate type and version
    if (certificate.getCertType() != (byte) 0x90) {
      throw new IllegalArgumentException(
          "Invalid certificate type: expected 0x90, got "
              + String.format("%02X", certificate.getCertType()));
    }
    if (certificate.getStructureVersion() != (byte) 0x01) {
      throw new IllegalArgumentException(
          "Invalid certificate version: expected 0x01, got "
              + String.format("%02X", certificate.getStructureVersion()));
    }

    // Verify the signature using the issuer's public key
    byte[] issuerKeyRef = certificate.getIssuerKeyReference();
    RSAPublicKey issuerPublicKey = getPublicKey(issuerKeyRef);
    if (issuerPublicKey == null) {
      throw new IllegalStateException(
          "Issuer public key not found in store: " + HexUtil.toHex(issuerKeyRef));
    }

    // Build the data that was signed (128 bytes)
    byte[] dataToVerify = certificate.toBytesForSigning();

    // Verify the signature
    if (!verifySignature(issuerPublicKey, dataToVerify, certificate.getSignature())) {
      throw new IllegalArgumentException("CA certificate signature verification failed");
    }

    // Extract the CA target key reference
    byte[] caTargetKeyRef = certificate.getCaTargetKeyReference();
    String keyRef = HexUtil.toHex(caTargetKeyRef);

    // Check if the key reference already exists
    checkKeyRefNotExists(keyRef);

    // Add the certificate to the store
    caCertificates.put(keyRef, certificate);

    return caTargetKeyRef;
  }

  /**
   * Verifies an RSA signature.
   *
   * @param publicKey The public key to verify with.
   * @param data The data that was signed.
   * @param signature The signature to verify.
   * @return true if the signature is valid, false otherwise.
   */
  private boolean verifySignature(RSAPublicKey publicKey, byte[] data, byte[] signature) {
    try {
      java.security.Signature sig = java.security.Signature.getInstance("NONEwithRSA");
      sig.initVerify(publicKey);
      sig.update(data);
      return sig.verify(signature);
    } catch (Exception e) {
      return false;
    }
  }

  /**
   * Retrieves a public key by its reference.
   *
   * @param publicKeyReference The reference to the public key.
   * @return The RSA public key associated with the reference, or null if not found.
   * @since 0.1.0
   */
  RSAPublicKey getPublicKey(byte[] publicKeyReference) {
    String keyRef = HexUtil.toHex(publicKeyReference);
    // First check PCA public keys
    RSAPublicKey pcaKey = pcaPublicKeys.get(keyRef);
    if (pcaKey != null) {
      return pcaKey;
    }
    // Then check CA certificates
    CaCertificate caCert = caCertificates.get(keyRef);
    if (caCert != null) {
      return caCert.getRsaPublicKey();
    }
    return null;
  }

  /**
   * Ensures that the provided key reference does not already exist in the store. If the key
   * reference exists in either the PCA public keys or the CA certificates, an {@link
   * IllegalStateException} is thrown.
   *
   * @param keyRef The key reference to be checked for uniqueness.
   * @throws IllegalStateException if the key reference already exists in the store.
   */
  private void checkKeyRefNotExists(String keyRef) {
    if (pcaPublicKeys.containsKey(keyRef) || caCertificates.containsKey(keyRef)) {
      throw new IllegalStateException(
          "Public key reference already exists in the store: " + keyRef);
    }
  }

  /**
   * Checks if a public key reference exists in the store.
   *
   * @param publicKeyReference The reference to check.
   * @return true if the reference exists, false otherwise.
   * @since 0.1.0
   */
  boolean containsPublicKeyReference(byte[] publicKeyReference) {
    String keyRef = HexUtil.toHex(publicKeyReference);
    return pcaPublicKeys.containsKey(keyRef) || caCertificates.containsKey(keyRef);
  }

  /**
   * Retrieves a CA certificate by its key reference.
   *
   * @param caKeyReference The CA key reference.
   * @return The CA certificate, or null if not found.
   * @since 0.1.0
   */
  CaCertificate getCaCertificate(byte[] caKeyReference) {
    return caCertificates.get(HexUtil.toHex(caKeyReference));
  }
}
