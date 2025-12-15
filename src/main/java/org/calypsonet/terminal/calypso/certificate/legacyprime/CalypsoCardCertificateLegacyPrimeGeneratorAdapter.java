/* **************************************************************************************
 * Copyright (c) 2024 Calypso Networks Association https://calypsonet.org/
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

import org.calypsonet.terminal.calypso.certificate.legacyprime.spi.CalypsoCertificateLegacyPrimeSigner;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.HexUtil;

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
    // Initialize the certificate builder with known values
    this.certificateBuilder =
        CardCertificate.builder()
            .certType((byte) 0x91)
            .structureVersion((byte) 0x01)
            .issuerKeyReference(issuerPublicKeyReference)
            .cardIndex(new byte[4]); // Default index = 0
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
        .isEqual(cardPublicKey.length, 64, "cardPublicKey length");

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
    Assert.getInstance().notNull(aid, "aid").isInRange(aid.length, 5, 16, "aid length");

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
    byte[] cardAidValue = new byte[16];
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
        .isEqual(serialNumber.length, 8, "serialNumber length");

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
        .isEqual(startupInfo.length, 7, "startupInfo length");

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
    byte[] cardIndex = new byte[4];
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

    // Verify that issuer public key exists in store
    if (!store.containsPublicKeyReference(issuerPublicKeyReference)) {
      throw new IllegalStateException(
          "Issuer public key reference not found in store: "
              + HexUtil.toHex(issuerPublicKeyReference));
    }

    // Extract issuer information from issuerPublicKeyReference (29 bytes)
    // Structure: issuerAidSize (1) + issuerAidValue (16) + issuerSerialNumber (8) + issuerKeyId (4)
    byte issuerAidSize = issuerPublicKeyReference[0];
    byte[] issuerAidValue = new byte[16];
    System.arraycopy(issuerPublicKeyReference, 1, issuerAidValue, 0, 16);
    byte[] issuerSerialNumber = new byte[8];
    System.arraycopy(issuerPublicKeyReference, 17, issuerSerialNumber, 0, 8);
    byte[] issuerKeyId = new byte[4];
    System.arraycopy(issuerPublicKeyReference, 25, issuerKeyId, 0, 4);

    // Build the certificate with extracted information
    certificateBuilder
        .issuerAidSize(issuerAidSize)
        .issuerAidValue(issuerAidValue)
        .issuerSerialNumber(issuerSerialNumber)
        .issuerKeyId(issuerKeyId)
        .cardRights((byte) 0)
        .cardRfu(new byte[18])
        .eccRfu(new byte[124]);

    // Build recoverable data (222 bytes) for ISO9796-2 signature
    byte[] recoverableData = buildRecoverableData();

    // Build the non-recoverable data for signature (60 bytes)
    byte[] nonRecoverableData = buildNonRecoverableData();

    // Sign using ISO9796-2 with recoverable data
    byte[] signedCertificate =
        signer.generateSignedCertificate(nonRecoverableData, recoverableData);

    // Extract signature from signed certificate (last 256 bytes)
    if (signedCertificate.length != nonRecoverableData.length + 256) {
      throw new IllegalStateException(
          "Signed certificate must be "
              + (nonRecoverableData.length + 256)
              + " bytes, got "
              + signedCertificate.length
              + " bytes");
    }

    byte[] signature = new byte[256];
    System.arraycopy(signedCertificate, nonRecoverableData.length, signature, 0, 256);

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
    byte[] data = new byte[222];
    int offset = 0;

    // KCertStartDate (4 bytes)
    byte[] startDate = tempCert.getStartDate();
    if (startDate != null) {
      System.arraycopy(startDate, 0, data, offset, 4);
    }
    offset += 4;

    // KCertEndDate (4 bytes)
    byte[] endDate = tempCert.getEndDate();
    if (endDate != null) {
      System.arraycopy(endDate, 0, data, offset, 4);
    }
    offset += 4;

    // KCertCardRights (1 byte)
    data[offset++] = tempCert.getCardRights();

    // KCertCardInfo (7 bytes)
    byte[] cardInfo = tempCert.getCardInfo();
    if (cardInfo != null) {
      System.arraycopy(cardInfo, 0, data, offset, 7);
    }
    offset += 7;

    // KCertCardRfu (18 bytes)
    byte[] cardRfu = tempCert.getCardRfu();
    System.arraycopy(cardRfu, 0, data, offset, 18);
    offset += 18;

    // KCertEccPublicKey (64 bytes)
    byte[] eccPublicKey = tempCert.getEccPublicKey();
    if (eccPublicKey != null) {
      System.arraycopy(eccPublicKey, 0, data, offset, 64);
    }
    offset += 64;

    // KCertEccRfu (124 bytes)
    byte[] eccRfu = tempCert.getEccRfu();
    System.arraycopy(eccRfu, 0, data, offset, 124);

    return data;
  }

  /**
   * Builds the non-recoverable data (60 bytes) for ISO9796-2 signature.
   *
   * @return The non-recoverable data.
   */
  private byte[] buildNonRecoverableData() {
    CardCertificate tempCert = certificateBuilder.build();
    byte[] data = new byte[60];
    int offset = 0;

    // KCertType (1 byte)
    data[offset++] = tempCert.getCertType();

    // KCertStructureVersion (1 byte)
    data[offset++] = tempCert.getStructureVersion();

    // KCertIssuerKeyReference (29 bytes)
    byte[] issuerKeyRef = tempCert.getIssuerKeyReference();
    System.arraycopy(issuerKeyRef, 0, data, offset, 29);
    offset += 29;

    // KCertCardAidSize (1 byte)
    data[offset++] = tempCert.getCardAidSize();

    // KCertCardAidValue (16 bytes)
    byte[] cardAidValue = tempCert.getCardAidValue();
    System.arraycopy(cardAidValue, 0, data, offset, 16);
    offset += 16;

    // KCertCardSerialNumber (8 bytes)
    byte[] cardSerialNumber = tempCert.getCardSerialNumber();
    if (cardSerialNumber != null) {
      System.arraycopy(cardSerialNumber, 0, data, offset, 8);
    }
    offset += 8;

    // KCertCardIndex (4 bytes)
    byte[] cardIndex = tempCert.getCardIndex();
    System.arraycopy(cardIndex, 0, data, offset, 4);

    return data;
  }

  /**
   * Serializes the Card certificate to a 316-byte array.
   *
   * @param certificate The certificate to serialize.
   * @return The serialized certificate.
   */
  private byte[] serializeCardCertificate(CardCertificate certificate) {
    byte[] serialized = new byte[316];
    int offset = 0;

    // KCertType (1 byte)
    serialized[offset++] = certificate.getCertType();

    // KCertStructureVersion (1 byte)
    serialized[offset++] = certificate.getStructureVersion();

    // KCertIssuerKeyReference (29 bytes)
    byte[] issuerKeyRef = certificate.getIssuerKeyReference();
    System.arraycopy(issuerKeyRef, 0, serialized, offset, 29);
    offset += 29;

    // KCertCardAidSize (1 byte)
    serialized[offset++] = certificate.getCardAidSize();

    // KCertCardAidValue (16 bytes)
    byte[] cardAidValue = certificate.getCardAidValue();
    System.arraycopy(cardAidValue, 0, serialized, offset, 16);
    offset += 16;

    // KCertCardSerialNumber (8 bytes)
    byte[] cardSerialNumber = certificate.getCardSerialNumber();
    if (cardSerialNumber != null) {
      System.arraycopy(cardSerialNumber, 0, serialized, offset, 8);
    }
    offset += 8;

    // KCertCardIndex (4 bytes)
    byte[] cardIndex = certificate.getCardIndex();
    System.arraycopy(cardIndex, 0, serialized, offset, 4);
    offset += 4;

    // KCertSignature (256 bytes)
    byte[] signature = certificate.getSignature();
    System.arraycopy(signature, 0, serialized, offset, 256);

    return serialized;
  }
}
