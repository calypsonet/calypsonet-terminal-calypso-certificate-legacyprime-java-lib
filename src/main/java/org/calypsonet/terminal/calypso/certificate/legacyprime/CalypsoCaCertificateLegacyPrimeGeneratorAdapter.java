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
  private final byte[] issuerPublicKeyReference;
  private final CalypsoCertificateLegacyPrimeSigner signer;
  private RSAPublicKey caPublicKey;
  private final CaCertificate issuerCaCertificate;
  private final CaCertificate.Builder certificateBuilder;

  private byte[] caPublicKeyReference;

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
    this.issuerPublicKeyReference = issuerPublicKeyReference.clone();
    this.signer = signer;
    this.issuerCaCertificate = store.getCaCertificate(issuerPublicKeyReference);
    // Initialize the certificate builder with known values
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
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CalypsoCaCertificateLegacyPrimeGenerator withCaPublicKey(
      byte[] caPublicKeyReference, RSAPublicKey caPublicKey) {
    Assert.getInstance()
        .notNull(caPublicKeyReference, "caPublicKeyReference")
        .isEqual(
            caPublicKeyReference.length,
            CertificateConstants.KEY_REFERENCE_SIZE,
            "caPublicKeyReference length");

    if (store.containsPublicKeyReference(caPublicKeyReference)) {
      throw new IllegalArgumentException("CA public key already exists in store");
    }

    // Validate CA AID against issuer constraints
    CertificateUtils.validateAidAgainstIssuerConstraints(caPublicKeyReference, issuerCaCertificate);

    this.caPublicKeyReference = caPublicKeyReference.clone();
    certificateBuilder.caTargetKeyReference(caPublicKeyReference).rsaPublicKey(caPublicKey);
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

    // Check consistency with issuer scope
    if (issuerCaCertificate != null) {
      CaScope issuerCaScope = issuerCaCertificate.getCaScope();
      CaScope targetCaScope = CaScope.fromByte(caScope);
      if (issuerCaScope != CaScope.NOT_SPECIFIED && targetCaScope != issuerCaScope) {
        throw new IllegalArgumentException(
            "Cannot generate a certificate with universal scope from an issuer with restricted scope.");
      }
    }

    certificateBuilder.caScope(caScope);
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
    if (caPublicKeyReference == null) {
      throw new IllegalStateException("CA public key must be set");
    }

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

    // Extract the public key header (first 34 bytes of RSA modulus)
    byte[] modulus = caPublicKey.getModulus().toByteArray();
    byte[] publicKeyHeader = new byte[CertificateConstants.PUBLIC_KEY_HEADER_SIZE];

    // Handle potential leading zero byte in modulus
    int srcPos = (modulus.length == 257 && modulus[0] == 0) ? 1 : 0;
    System.arraycopy(
        modulus, srcPos, publicKeyHeader, 0, CertificateConstants.PUBLIC_KEY_HEADER_SIZE);

    certificateBuilder.publicKeyHeader(publicKeyHeader);

    // Build certificate bytes for signing (128 bytes from KCertType to KCertPublicKeyHeader)
    byte[] dataToSign = buildCertificateDataForSigning();

    // extract recoverable data (last 222 bytes of RSA modulus)
    byte[] recoverableData = new byte[CertificateConstants.RECOVERABLE_DATA_SIZE];
    System.arraycopy(
        modulus,
        srcPos + CertificateConstants.PUBLIC_KEY_HEADER_SIZE,
        recoverableData,
        0,
        CertificateConstants.PUBLIC_KEY_HEADER_SIZE);

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

    return signedCertificate;
  }

  /**
   * Builds the certificate data to be signed (128 bytes).
   *
   * @return The data to sign.
   */
  private byte[] buildCertificateDataForSigning() {
    CaCertificate tempCert = certificateBuilder.build();
    return tempCert.toBytesForSigning();
  }

  /**
   * Serializes the CA certificate to a 384-byte array.
   *
   * @param certificate The certificate to serialize.
   * @return The serialized certificate.
   */
  private byte[] serializeCaCertificate(CaCertificate certificate) {
    return certificate.toBytes();
  }
}
