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
import java.time.LocalDate;
import org.calypsonet.terminal.calypso.certificate.legacyprime.spi.CalypsoCertificateLegacyPrimeSigner;
import org.eclipse.keyple.core.util.Assert;

/**
 * Adapter implementation of {@link CalypsoCaCertificateLegacyPrimeGenerator}.
 *
 * <p>This class provides a builder pattern for creating Calypso Prime Legacy CA certificates with
 * configurable parameters.
 *
 * @since 0.1.0
 */
final class CalypsoCaCertificateLegacyPrimeGeneratorAdapter
    implements CalypsoCaCertificateLegacyPrimeGenerator {

  private final CalypsoCertificateLegacyPrimeStoreAdapter store;
  private final CalypsoCertificateLegacyPrimeSigner signer;
  private RSAPublicKey caPublicKey;
  private final CaCertificate issuerCaCertificate;
  private final CaCertificate.Builder certificateBuilder;

  /**
   * Creates a new generator instance.
   *
   * @param store The store containing the issuer certificates.
   * @param issuerPublicKeyReference The reference to the issuer's public key.
   * @param signer The signer to use for certificate signing.
   * @since 0.1.0
   */
  CalypsoCaCertificateLegacyPrimeGeneratorAdapter(
      CalypsoCertificateLegacyPrimeStoreAdapter store,
      byte[] issuerPublicKeyReference,
      CalypsoCertificateLegacyPrimeSigner signer) {
    this.store = store;
    this.signer = signer;
    this.issuerCaCertificate = store.getCaCertificate(issuerPublicKeyReference);
    // Initialize the certificate builder with known and default values
    this.certificateBuilder =
        CaCertificate.builder()
            .certType(CertificateConstants.CERT_TYPE_CA)
            .structureVersion(CertificateConstants.STRUCTURE_VERSION)
            .issuerKeyReference(issuerPublicKeyReference)
            .startDate(new byte[CertificateConstants.DATE_SIZE])
            .caRfu1(new byte[CertificateConstants.CA_RFU1_SIZE])
            .caRights(CaRights.CA_RIGHTS_NOT_SPECIFIED)
            .caScope(CaScope.NOT_SPECIFIED.getValue())
            .endDate(new byte[CertificateConstants.DATE_SIZE])
            .caTargetAidValue(new byte[CertificateConstants.AID_VALUE_SIZE])
            .caOperatingMode(OperatingMode.TRUNCATION_FORBIDDEN.getValue())
            .caRfu2(new byte[CertificateConstants.CA_RFU2_SIZE]);
  }

  /**
   * Validates that the CA AID respects the issuer's constraints.
   *
   * <p>According to the Calypso specification (KCertCaOperatingMode):
   *
   * <ul>
   *   <li>If issuer has no target AID specified (is null), no validation is performed
   *   <li>If truncation is forbidden (bit b0 = 0): CA AID must exactly match issuer's target AID
   *   <li>If truncation is allowed (bit b0 = 1): CA AID must start with issuer's target AID
   * </ul>
   *
   * @param caPublicKeyReference The CA public key reference containing the CA AID.
   * @throws IllegalArgumentException if the CA AID does not respect issuer's constraints.
   */
  static void validateAidAgainstIssuerConstraints(
      byte[] caPublicKeyReference, CaCertificate issuerCaCertificate) {

    Aid issuerTargetAid = issuerCaCertificate.getCaTargetAid();

    // If issuer has no specific target AID (is null or RFU), no validation needed
    if (issuerTargetAid == null || issuerTargetAid.isRfu()) {
      return;
    }

    // Extract CA AID from caPublicKeyReference
    KeyReference keyReference = KeyReference.fromBytes(caPublicKeyReference);
    Aid caAid = keyReference.getAid();

    // Get issuer's operating mode
    OperatingMode issuerOperatingMode = issuerCaCertificate.getCaOperatingMode();

    if (!caAid.matches(issuerTargetAid, issuerOperatingMode)) {
      throw new IllegalArgumentException(
          "CA AID '"
              + caAid
              + "' does not match issuer's target AID constraints (issuer AID: '"
              + issuerTargetAid
              + "', mode: "
              + issuerOperatingMode
              + ").");
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CalypsoCaCertificateLegacyPrimeGenerator withCaPublicKey(
      byte[] caPublicKeyReference, RSAPublicKey caPublicKey) {
    certificateBuilder.caTargetKeyReference(caPublicKeyReference).rsaPublicKey(caPublicKey);
    if (store.containsPublicKeyReference(caPublicKeyReference)) {
      throw new IllegalArgumentException("CA public key already exists in store");
    }
    if (issuerCaCertificate != null) {
      validateAidAgainstIssuerConstraints(caPublicKeyReference, issuerCaCertificate);
    }
    this.caPublicKey = caPublicKey;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CalypsoCaCertificateLegacyPrimeGenerator withStartDate(int year, int month, int day) {
    Assert.getInstance()
        .isInRange(year, 0, 9999, "year")
        .isInRange(month, 1, 12, "month")
        .isInRange(day, 1, 31, "day");
    certificateBuilder.startDate(CertificateUtils.encodeDateBcd(year, month, day));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CalypsoCaCertificateLegacyPrimeGenerator withEndDate(int year, int month, int day) {
    Assert.getInstance()
        .isInRange(year, 0, 9999, "year")
        .isInRange(month, 1, 12, "month")
        .isInRange(day, 1, 31, "day");
    certificateBuilder.endDate(CertificateUtils.encodeDateBcd(year, month, day));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CalypsoCaCertificateLegacyPrimeGenerator withTargetAid(byte[] aid, boolean isTruncated) {
    certificateBuilder
        .caTargetAidValue(aid)
        .caOperatingMode(
            isTruncated
                ? OperatingMode.TRUNCATION_ALLOWED.getValue()
                : OperatingMode.TRUNCATION_FORBIDDEN.getValue());
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CalypsoCaCertificateLegacyPrimeGenerator withCaRights(byte caRights) {
    certificateBuilder.caRights(caRights);
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CalypsoCaCertificateLegacyPrimeGenerator withCaScope(byte caScope) {
    certificateBuilder.caScope(caScope);
    if (issuerCaCertificate != null) {
      CaScope issuerCaScope = issuerCaCertificate.getCaScope();
      CaScope targetCaScope = CaScope.fromByte(caScope);
      if (issuerCaScope != CaScope.NOT_SPECIFIED && targetCaScope != issuerCaScope) {
        throw new IllegalArgumentException(
            "Cannot generate a certificate with universal scope from an issuer with restricted scope.");
      }
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public byte[] generate() {
    // Validate required parameters
    if (caPublicKey == null) {
      throw new IllegalStateException("CA public key must be set");
    }

    // Validate time checks
    if (issuerCaCertificate != null) {
      // Check validity period
      LocalDate today = LocalDate.now();
      LocalDate startDate = issuerCaCertificate.getStartDate();
      if (startDate != null && today.isBefore(startDate)) {
        throw new IllegalStateException("Issuer CA certificate is not yet valid.");
      }
      LocalDate endDate = issuerCaCertificate.getEndDate();
      if (endDate != null && today.isAfter(endDate)) {
        throw new IllegalStateException("Issuer CA certificate has expired.");
      }
    }

    // Set the public key header into the builder and build recoverable data
    byte[] recoverableData = setPublicKeyHeaderAndBuildRecoverableData();

    // Build certificate bytes for signing (128 bytes from KCertType to KCertPublicKeyHeader)
    byte[] dataToSign = certificateBuilder.build().toBytesForSigning();

    // Sign the data using the signer (no recoverable data for CA certificates)
    byte[] signedCertificate = signer.generateSignedCertificate(dataToSign, recoverableData);

    // Extract signature from a signed certificate (last 256 bytes)
    if (signedCertificate.length != dataToSign.length + CertificateConstants.RSA_SIGNATURE_SIZE) {
      throw new CertificateSigningException(
          "Signed certificate must be "
              + (dataToSign.length + CertificateConstants.RSA_SIGNATURE_SIZE)
              + " bytes, got "
              + signedCertificate.length
              + " bytes");
    }

    // Check if something was altered during signing
    for (int i = 0; i < dataToSign.length; i++) {
      if (dataToSign[i] != signedCertificate[i]) {
        throw new CertificateSigningException("Certificate signing failed");
      }
    }

    return signedCertificate;
  }

  /**
   * Extracts the public key header from the modulus of the CA public key and sets it within the
   * certificate builder. Additionally, builds and returns the recoverable data from the modulus.
   *
   * <p>The public key header consists of the first 34 bytes of the RSA modulus, while the
   * recoverable data comprises the subsequent 222 bytes. If the modulus is 257 bytes long and
   * starts with a leading zero (due to encoding), this leading zero is excluded in the extraction
   * process.
   *
   * @return A byte array containing the recoverable data extracted from the modulus, which is 222
   *     bytes in length.
   */
  private byte[] setPublicKeyHeaderAndBuildRecoverableData() {

    // Extract the public key header (first 34 bytes of RSA modulus)
    byte[] modulus = caPublicKey.getModulus().toByteArray();
    byte[] publicKeyHeader = new byte[CertificateConstants.PUBLIC_KEY_HEADER_SIZE];

    // Handle potential leading zero byte in modulus
    int srcPos = (modulus.length == 257 && modulus[0] == 0) ? 1 : 0;
    System.arraycopy(
        modulus, srcPos, publicKeyHeader, 0, CertificateConstants.PUBLIC_KEY_HEADER_SIZE);

    certificateBuilder.publicKeyHeader(publicKeyHeader);

    // extract recoverable data (last 222 bytes of RSA modulus)
    byte[] recoverableData = new byte[CertificateConstants.RECOVERABLE_DATA_SIZE];
    System.arraycopy(
        modulus,
        srcPos + CertificateConstants.PUBLIC_KEY_HEADER_SIZE,
        recoverableData,
        0,
        CertificateConstants.PUBLIC_KEY_HEADER_SIZE);
    return recoverableData;
  }
}
