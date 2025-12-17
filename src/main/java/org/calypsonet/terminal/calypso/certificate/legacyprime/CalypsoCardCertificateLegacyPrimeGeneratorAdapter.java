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

  private final CalypsoCertificateLegacyPrimeStoreAdapter store;
  private final byte[] issuerPublicKeyReference;
  private final CalypsoCertificateLegacyPrimeSigner signer;
  private final CaCertificate issuerCaCertificate;
  private final CardCertificate.Builder certificateBuilder;

  private boolean cardPublicKeySet = false;
  private boolean cardAidSet = false;
  private boolean cardSerialNumberSet = false;
  private boolean cardStartupInfoSet = false;

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
    this.store = store;
    this.issuerPublicKeyReference = issuerPublicKeyReference.clone();
    this.signer = signer;
    this.issuerCaCertificate = store.getCaCertificate(issuerPublicKeyReference);
    // Initialize the certificate builder with known values
    this.certificateBuilder =
        CardCertificate.builder()
            .certType(CertificateConstants.CERT_TYPE_CARD)
            .structureVersion(CertificateConstants.STRUCTURE_VERSION)
            .issuerKeyReference(issuerPublicKeyReference)
            .cardIndex(new byte[CertificateConstants.CARD_INDEX_SIZE]); // Default index = 0
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

    certificateBuilder.eccPublicKey(cardPublicKey);
    cardPublicKeySet = true;
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
    Assert.getInstance()
        .notNull(aid, "aid")
        .isInRange(
            aid.length,
            CertificateConstants.AID_MIN_LENGTH,
            CertificateConstants.AID_MAX_LENGTH,
            "aid length");

    // Check if AID contains only zero bytes
    boolean allZeros = true;
    for (byte b : aid) {
      if (b != 0) {
        allZeros = false;
        break;
      }
    }
    Assert.getInstance().isTrue(!allZeros, "AID cannot contain only zero bytes");

    // Prepare padded AID value
    byte cardAidSize = (byte) aid.length;
    byte[] cardAidValue = new byte[CertificateConstants.AID_VALUE_SIZE];
    System.arraycopy(aid, 0, cardAidValue, 0, aid.length);

    certificateBuilder.cardAidSize(cardAidSize).cardAidValue(cardAidValue);
    cardAidSet = true;
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
    cardSerialNumberSet = true;
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
    cardStartupInfoSet = true;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CalypsoCardCertificateLegacyPrimeGenerator withIndex(int index) {
    // Encode index as 4-byte big-endian
    byte[] cardIndex = new byte[CertificateConstants.CARD_INDEX_SIZE];
    cardIndex[0] = (byte) (index >> 24);
    cardIndex[1] = (byte) (index >> 16);
    cardIndex[2] = (byte) (index >> 8);
    cardIndex[3] = (byte) index;

    certificateBuilder.cardIndex(cardIndex);
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
    if (!cardPublicKeySet) {
      throw new IllegalStateException("Card public key must be set");
    }

    if (!cardAidSet) {
      throw new IllegalStateException("Card AID must be set");
    }

    if (!cardSerialNumberSet) {
      throw new IllegalStateException("Card serial number must be set");
    }

    if (!cardStartupInfoSet) {
      throw new IllegalStateException("Card startup info must be set");
    }

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

    // issuerPublicKeyReference will be converted to KeyReference by the builder
    certificateBuilder
        .issuerKeyReference(issuerPublicKeyReference)
        .cardRights((byte) 0)
        .cardRfu(new byte[CertificateConstants.CARD_RFU_SIZE])
        .eccRfu(new byte[CertificateConstants.ECC_RFU_SIZE]);

    // Build recoverable data (222 bytes) for ISO9796-2 signature
    byte[] recoverableData = buildRecoverableData();

    // Build the non-recoverable data for signature (60 bytes)
    byte[] nonRecoverableData = buildNonRecoverableData();

    // Sign using ISO9796-2 with recoverable data
    byte[] signedCertificate =
        signer.generateSignedCertificate(nonRecoverableData, recoverableData);

    // Extract signature from signed certificate (last 256 bytes)
    if (signedCertificate.length
        != nonRecoverableData.length + CertificateConstants.RSA_SIGNATURE_SIZE) {
      throw new IllegalStateException(
          "Signed certificate must be "
              + (nonRecoverableData.length + CertificateConstants.RSA_SIGNATURE_SIZE)
              + " bytes, got "
              + signedCertificate.length
              + " bytes");
    }

    byte[] signature = new byte[CertificateConstants.RSA_SIGNATURE_SIZE];
    System.arraycopy(
        signedCertificate,
        nonRecoverableData.length,
        signature,
        0,
        CertificateConstants.RSA_SIGNATURE_SIZE);

    certificateBuilder.signature(signature);

    // Build the final certificate
    CardCertificate certificate = certificateBuilder.build();

    // Serialize certificate to 316-byte array
    return serializeCardCertificate(certificate);
  }

  /**
   * Builds the recoverable data (222 bytes) for ISO9796-2 signature.
   *
   * @return The recoverable data.
   */
  private byte[] buildRecoverableData() {
    CardCertificate tempCert = certificateBuilder.build();
    return tempCert.getRecoverableDataForSigning();
  }

  /**
   * Builds the non-recoverable data (60 bytes) for ISO9796-2 signature.
   *
   * @return The non-recoverable data.
   */
  private byte[] buildNonRecoverableData() {
    CardCertificate tempCert = certificateBuilder.build();
    return tempCert.toBytesForSigning();
  }

  /**
   * Serializes the Card certificate to a 316-byte array.
   *
   * @param certificate The certificate to serialize.
   * @return The serialized certificate.
   */
  private byte[] serializeCardCertificate(CardCertificate certificate) {
    return certificate.toBytes();
  }
}
