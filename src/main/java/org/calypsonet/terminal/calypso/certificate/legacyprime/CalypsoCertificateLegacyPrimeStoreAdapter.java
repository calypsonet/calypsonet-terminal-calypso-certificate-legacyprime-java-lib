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
        .isEqual(
            pcaPublicKey.getModulus().bitLength(),
            CertificateConstants.RSA_MODULUS_BIT_LENGTH,
            "PCA public key modulus bit length")
        .isEqual(
            pcaPublicKey.getPublicExponent().intValue(),
            CertificateConstants.RSA_PUBLIC_EXPONENT,
            "PCA public key exponent");

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
        .isEqual(
            pcaPublicKeyModulus.length,
            CertificateConstants.RSA_MODULUS_SIZE,
            "pcaPublicKeyModulus length");

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
        .isEqual(
            caCertificate.length, CertificateConstants.CA_CERTIFICATE_SIZE, "caCertificate length");

    // Manually extract the issuer key reference to find the public key needed for parsing
    byte[] issuerKeyRef = new byte[CertificateConstants.KEY_REFERENCE_SIZE];
    System.arraycopy(
        caCertificate,
        2, // Offset of KCertIssuerKeyReference (Type + Version)
        issuerKeyRef,
        0,
        CertificateConstants.KEY_REFERENCE_SIZE);
    RSAPublicKey issuerPublicKey = getPublicKey(issuerKeyRef);
    if (issuerPublicKey == null) {
      throw new IllegalStateException(
          "Issuer public key not found in store: " + HexUtil.toHex(issuerKeyRef));
    }

    // Parse the CA certificate using the issuer's public key
    CaCertificate certificate = CaCertificate.fromBytes(caCertificate, issuerPublicKey);

    // Verify certificate type and version
    if (certificate.getCertType() != CertificateConstants.CERT_TYPE_CA) {
      throw new IllegalArgumentException(
          "Invalid certificate type: expected 0x90, got "
              + HexUtil.toHex(certificate.getCertType()));
    }
    if (certificate.getStructureVersion() != CertificateConstants.STRUCTURE_VERSION) {
      throw new IllegalArgumentException(
          "Invalid certificate version: expected 0x01, got "
              + HexUtil.toHex(certificate.getStructureVersion()));
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
