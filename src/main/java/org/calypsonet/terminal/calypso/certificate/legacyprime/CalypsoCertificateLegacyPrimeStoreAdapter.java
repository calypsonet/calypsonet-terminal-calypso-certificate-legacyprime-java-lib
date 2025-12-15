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
    if (pcaPublicKeys.containsKey(keyRef) || caCertificates.containsKey(keyRef)) {
      throw new IllegalStateException(
          "Public key reference already exists in the store: " + keyRef);
    }

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
    if (pcaPublicKeys.containsKey(keyRef) || caCertificates.containsKey(keyRef)) {
      throw new IllegalStateException(
          "Public key reference already exists in the store: " + keyRef);
    }

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
    CaCertificate certificate = parseCaCertificate(caCertificate);

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
    byte[] dataToVerify = buildCaCertificateDataForVerification(certificate);

    // Verify the signature
    if (!verifySignature(issuerPublicKey, dataToVerify, certificate.getSignature())) {
      throw new IllegalArgumentException("CA certificate signature verification failed");
    }

    // Extract the CA target key reference
    byte[] caTargetKeyRef = certificate.getCaTargetKeyReference();
    String keyRef = HexUtil.toHex(caTargetKeyRef);

    // Check if the key reference already exists
    if (pcaPublicKeys.containsKey(keyRef) || caCertificates.containsKey(keyRef)) {
      throw new IllegalStateException(
          "Public key reference already exists in the store: " + keyRef);
    }

    // Add the certificate to the store
    caCertificates.put(keyRef, certificate);

    return caTargetKeyRef;
  }

  /**
   * Parses a CA certificate from its byte array representation.
   *
   * @param caCertificate The 384-byte certificate.
   * @return The parsed CA certificate.
   */
  private CaCertificate parseCaCertificate(byte[] caCertificate) {
    int offset = 0;

    // KCertType (1 byte)
    byte certType = caCertificate[offset++];

    // KCertStructureVersion (1 byte)
    byte structureVersion = caCertificate[offset++];

    // KCertIssuerKeyReference (29 bytes)
    byte[] issuerKeyReference = new byte[29];
    System.arraycopy(caCertificate, offset, issuerKeyReference, 0, 29);
    offset += 29;

    // KCertCaTargetKeyReference (29 bytes)
    byte[] caTargetKeyReference = new byte[29];
    System.arraycopy(caCertificate, offset, caTargetKeyReference, 0, 29);
    offset += 29;

    // Extract fields from caTargetKeyReference
    byte caAidSize = caTargetKeyReference[0];
    byte[] caAidValue = new byte[16];
    System.arraycopy(caTargetKeyReference, 1, caAidValue, 0, 16);
    byte[] caSerialNumber = new byte[8];
    System.arraycopy(caTargetKeyReference, 17, caSerialNumber, 0, 8);
    byte[] caKeyId = new byte[4];
    System.arraycopy(caTargetKeyReference, 25, caKeyId, 0, 4);

    // KCertStartDate (4 bytes)
    byte[] startDate = new byte[4];
    System.arraycopy(caCertificate, offset, startDate, 0, 4);
    offset += 4;

    // KCertCaRfu1 (4 bytes)
    byte[] caRfu1 = new byte[4];
    System.arraycopy(caCertificate, offset, caRfu1, 0, 4);
    offset += 4;

    // KCertCaRights (1 byte)
    byte caRights = caCertificate[offset++];

    // KCertCaScope (1 byte)
    byte caScope = caCertificate[offset++];

    // KCertEndDate (4 bytes)
    byte[] endDate = new byte[4];
    System.arraycopy(caCertificate, offset, endDate, 0, 4);
    offset += 4;

    // KCertCaTargetAidSize (1 byte)
    byte caTargetAidSize = caCertificate[offset++];

    // KCertCaTargetAidValue (16 bytes)
    byte[] caTargetAidValue = new byte[16];
    System.arraycopy(caCertificate, offset, caTargetAidValue, 0, 16);
    offset += 16;

    // KCertCaOperatingMode (1 byte)
    byte caOperatingMode = caCertificate[offset++];

    // KCertCaRfu2 (2 bytes)
    byte[] caRfu2 = new byte[2];
    System.arraycopy(caCertificate, offset, caRfu2, 0, 2);
    offset += 2;

    // KCertPublicKeyHeader (34 bytes)
    byte[] publicKeyHeader = new byte[34];
    System.arraycopy(caCertificate, offset, publicKeyHeader, 0, 34);
    offset += 34;

    // KCertSignature (256 bytes)
    byte[] signature = new byte[256];
    System.arraycopy(caCertificate, offset, signature, 0, 256);

    // Reconstruct the RSA public key from the public key header
    RSAPublicKey rsaPublicKey = reconstructRsaPublicKey(publicKeyHeader, signature);

    return CaCertificate.builder()
        .certType(certType)
        .structureVersion(structureVersion)
        .issuerKeyReference(issuerKeyReference)
        .caTargetKeyReference(caTargetKeyReference)
        .caAidSize(caAidSize)
        .caAidValue(caAidValue)
        .caSerialNumber(caSerialNumber)
        .caKeyId(caKeyId)
        .startDate(startDate)
        .caRfu1(caRfu1)
        .caRights(caRights)
        .caScope(caScope)
        .endDate(endDate)
        .caTargetAidSize(caTargetAidSize)
        .caTargetAidValue(caTargetAidValue)
        .caOperatingMode(caOperatingMode)
        .caRfu2(caRfu2)
        .publicKeyHeader(publicKeyHeader)
        .signature(signature)
        .rsaPublicKey(rsaPublicKey)
        .build();
  }

  /**
   * Reconstructs the RSA public key from the public key header and signature.
   *
   * @param publicKeyHeader The first 34 bytes of the modulus.
   * @param signature The 256-byte signature containing the remaining modulus bytes.
   * @return The reconstructed RSA public key.
   */
  private RSAPublicKey reconstructRsaPublicKey(byte[] publicKeyHeader, byte[] signature) {
    // The modulus is 256 bytes total: 34 bytes from header + 222 bytes from signature
    byte[] modulus = new byte[256];
    System.arraycopy(publicKeyHeader, 0, modulus, 0, 34);
    // The last 222 bytes of the signature encode the remaining modulus bytes
    // (This is part of the RSA signature scheme where data is encoded in the signature)
    System.arraycopy(signature, 34, modulus, 34, 222);

    return CertificateUtils.generateRSAPublicKeyFromModulus(modulus);
  }

  /**
   * Builds the certificate data for signature verification (128 bytes).
   *
   * @param certificate The certificate.
   * @return The data that was signed.
   */
  private byte[] buildCaCertificateDataForVerification(CaCertificate certificate) {
    byte[] data = new byte[128];
    int offset = 0;

    // KCertType (1 byte)
    data[offset++] = certificate.getCertType();

    // KCertStructureVersion (1 byte)
    data[offset++] = certificate.getStructureVersion();

    // KCertIssuerKeyReference (29 bytes)
    byte[] issuerKeyRef = certificate.getIssuerKeyReference();
    System.arraycopy(issuerKeyRef, 0, data, offset, 29);
    offset += 29;

    // KCertCaTargetKeyReference (29 bytes)
    byte[] caTargetKeyRef = certificate.getCaTargetKeyReference();
    System.arraycopy(caTargetKeyRef, 0, data, offset, 29);
    offset += 29;

    // KCertStartDate (4 bytes)
    byte[] startDate = certificate.getStartDate();
    System.arraycopy(startDate, 0, data, offset, 4);
    offset += 4;

    // KCertCaRfu1 (4 bytes)
    byte[] caRfu1 = certificate.getCaRfu1();
    System.arraycopy(caRfu1, 0, data, offset, 4);
    offset += 4;

    // KCertCaRights (1 byte)
    data[offset++] = certificate.getCaRights();

    // KCertCaScope (1 byte)
    data[offset++] = certificate.getCaScope();

    // KCertEndDate (4 bytes)
    byte[] endDate = certificate.getEndDate();
    System.arraycopy(endDate, 0, data, offset, 4);
    offset += 4;

    // KCertCaTargetAidSize (1 byte)
    data[offset++] = certificate.getCaTargetAidSize();

    // KCertCaTargetAidValue (16 bytes)
    byte[] caTargetAidValue = certificate.getCaTargetAidValue();
    System.arraycopy(caTargetAidValue, 0, data, offset, 16);
    offset += 16;

    // KCertCaOperatingMode (1 byte)
    data[offset++] = certificate.getCaOperatingMode();

    // KCertCaRfu2 (2 bytes)
    byte[] caRfu2 = certificate.getCaRfu2();
    System.arraycopy(caRfu2, 0, data, offset, 2);
    offset += 2;

    // KCertPublicKeyHeader (34 bytes)
    byte[] publicKeyHeader = certificate.getPublicKeyHeader();
    System.arraycopy(publicKeyHeader, 0, data, offset, 34);

    return data;
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
