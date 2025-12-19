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

import java.time.LocalDate;
import org.calypsonet.terminal.calypso.certificate.legacyprime.spi.CalypsoCertificateLegacyPrimeSigner;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.ByteArrayUtil;

/**
 * Adapter implementation of {@link CalypsoCardCertificateLegacyPrimeGenerator}.
 *
 * <p>This class provides a builder pattern for creating Calypso Prime Legacy card certificates with
 * configurable parameters.
 *
 * @since 0.1.0
 */
final class CalypsoCardCertificateLegacyPrimeGeneratorAdapter
    implements CalypsoCardCertificateLegacyPrimeGenerator {

  private final CalypsoCertificateLegacyPrimeSigner signer;
  private final CaCertificate issuerCaCertificate;
  private final CardCertificate.Builder certificateBuilder;

  /**
   * Creates a new generator instance.
   *
   * @param store The store containing the issuer certificates.
   * @param issuerPublicKeyReference The reference to the issuer's public key.
   * @param signer The signer to use for certificate signing.
   * @since 0.1.0
   */
  CalypsoCardCertificateLegacyPrimeGeneratorAdapter(
      CalypsoCertificateLegacyPrimeStoreAdapter store,
      byte[] issuerPublicKeyReference,
      CalypsoCertificateLegacyPrimeSigner signer) {
    this.signer = signer;
    this.issuerCaCertificate = store.getCaCertificate(issuerPublicKeyReference);
    // Initialize the certificate builder with known values
    this.certificateBuilder =
        CardCertificate.builder()
            .certType(CertificateConstants.CERT_TYPE_CARD)
            .structureVersion(CertificateConstants.STRUCTURE_VERSION_01)
            .issuerKeyReference(issuerPublicKeyReference)
            .cardIndex(new byte[CertificateConstants.CARD_INDEX_SIZE]) // Default index = 0
            .startDate(new byte[CertificateConstants.DATE_SIZE])
            .endDate(new byte[CertificateConstants.DATE_SIZE])
            .cardRights((byte) 0x00)
            .cardRfu(new byte[CertificateConstants.CARD_RFU_SIZE])
            .eccRfu(new byte[CertificateConstants.ECC_RFU_SIZE]);
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CalypsoCardCertificateLegacyPrimeGenerator withCardPublicKey(byte[] cardPublicKey) {
    Assert.getInstance()
        .notNull(cardPublicKey, "cardPublicKey")
        .isEqual(
            cardPublicKey.length, CertificateConstants.ECC_PUBLIC_KEY_SIZE, "cardPublicKey length");
    // TODO check consistency ?
    certificateBuilder.eccPublicKey(cardPublicKey);
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CalypsoCardCertificateLegacyPrimeGenerator withStartDate(int year, int month, int day) {
    Assert.getInstance()
        .isInRange(year, 0, 9999, "year")
        .isInRange(month, 1, 99, "month")
        .isInRange(day, 1, 99, "day");
    certificateBuilder.startDate(CertificateUtils.encodeDateBcd(year, month, day));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CalypsoCardCertificateLegacyPrimeGenerator withEndDate(int year, int month, int day) {
    Assert.getInstance()
        .isInRange(year, 0, 9999, "year")
        .isInRange(month, 1, 99, "month")
        .isInRange(day, 1, 99, "day");
    certificateBuilder.endDate(CertificateUtils.encodeDateBcd(year, month, day));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CalypsoCardCertificateLegacyPrimeGenerator withCardAid(byte[] aid) {
    certificateBuilder.cardAidUnpaddedValue(aid);
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CalypsoCardCertificateLegacyPrimeGenerator withCardSerialNumber(byte[] serialNumber) {
    Assert.getInstance()
        .notNull(serialNumber, "serialNumber")
        .isEqual(
            serialNumber.length, CertificateConstants.SERIAL_NUMBER_SIZE, "serialNumber length");
    certificateBuilder.cardSerialNumber(serialNumber);
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CalypsoCardCertificateLegacyPrimeGenerator withCardStartupInfo(byte[] startupInfo) {
    Assert.getInstance()
        .notNull(startupInfo, "startupInfo")
        .isEqual(
            startupInfo.length, CertificateConstants.CARD_STARTUP_INFO_SIZE, "startupInfo length");
    certificateBuilder.cardInfo(startupInfo);
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CalypsoCardCertificateLegacyPrimeGenerator withIndex(int index) {
    certificateBuilder.cardIndex(ByteArrayUtil.extractBytes(index, 4));
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
    CardCertificate cardCertificate = certificateBuilder.build();

    // Validate time checks
    if (issuerCaCertificate != null) {
      // Check validity period
      LocalDate today = LocalDate.now();
      LocalDate startDate = issuerCaCertificate.getStartDate();
      if (startDate != null && today.isBefore(startDate)) {
        throw new IllegalStateException("Issuer certificate is not yet valid.");
      }
      LocalDate endDate = issuerCaCertificate.getEndDate();
      if (endDate != null && today.isAfter(endDate)) {
        throw new IllegalStateException("Issuer certificate has expired.");
      }
    }

    // Build the non-recoverable data for signature (60 bytes)
    byte[] dataToSign = cardCertificate.toBytesForSigning();

    // Build recoverable data (222 bytes) for ISO9796-2 signature
    byte[] recoverableData = cardCertificate.getRecoverableDataForSigning();

    // Generate the signed certificate
    return CertificateUtils.generateSignedCertificate(dataToSign, recoverableData, signer);
  }
}
