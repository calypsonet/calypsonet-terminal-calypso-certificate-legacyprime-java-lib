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

/**
 * Internal class representing a Card Certificate with all its fields.
 *
 * <p>This class stores all fields from a 316-byte Card certificate according to the Calypso Prime
 * Legacy specification.
 *
 * @since 0.1.0
 */
final class CardCertificate {
  private final byte certType;
  private final byte structureVersion;
  private final byte[] issuerKeyReference;
  private final byte issuerAidSize;
  private final byte[] issuerAidValue;
  private final byte[] issuerSerialNumber;
  private final byte[] issuerKeyId;
  private final byte cardAidSize;
  private final byte[] cardAidValue;
  private final byte[] cardSerialNumber;
  private final byte[] cardIndex;
  private final byte[] signature;
  // Recoverable data from signature
  private final LocalDate startDate;
  private final LocalDate endDate;
  private final byte cardRights;
  private final byte[] cardInfo;
  private final byte[] cardRfu;
  private final byte[] eccPublicKey;
  private final byte[] eccRfu;

  /**
   * Creates a new Card certificate instance.
   *
   * @param builder The builder containing all certificate fields.
   * @since 0.1.0
   */
  private CardCertificate(Builder builder) {
    this.certType = builder.certType;
    this.structureVersion = builder.structureVersion;
    this.issuerKeyReference =
        builder.issuerKeyReference != null ? builder.issuerKeyReference.clone() : null;
    this.issuerAidSize = builder.issuerAidSize;
    this.issuerAidValue = builder.issuerAidValue != null ? builder.issuerAidValue.clone() : null;
    this.issuerSerialNumber =
        builder.issuerSerialNumber != null ? builder.issuerSerialNumber.clone() : null;
    this.issuerKeyId = builder.issuerKeyId != null ? builder.issuerKeyId.clone() : null;
    this.cardAidSize = builder.cardAidSize;
    this.cardAidValue = builder.cardAidValue != null ? builder.cardAidValue.clone() : null;
    this.cardSerialNumber =
        builder.cardSerialNumber != null ? builder.cardSerialNumber.clone() : null;
    this.cardIndex = builder.cardIndex != null ? builder.cardIndex.clone() : null;
    this.signature = builder.signature != null ? builder.signature.clone() : null;
    this.startDate =
        builder.startDate != null ? CertificateUtils.decodeDateBcd(builder.startDate) : null;
    this.endDate = builder.endDate != null ? CertificateUtils.decodeDateBcd(builder.endDate) : null;
    this.cardRights = builder.cardRights;
    this.cardInfo = builder.cardInfo != null ? builder.cardInfo.clone() : null;
    this.cardRfu = builder.cardRfu != null ? builder.cardRfu.clone() : null;
    this.eccPublicKey = builder.eccPublicKey != null ? builder.eccPublicKey.clone() : null;
    this.eccRfu = builder.eccRfu != null ? builder.eccRfu.clone() : null;
  }

  /**
   * Gets the certificate type.
   *
   * @return The certificate type (0x91).
   * @since 0.1.0
   */
  byte getCertType() {
    return certType;
  }

  /**
   * Gets the structure version.
   *
   * @return The structure version (0x01).
   * @since 0.1.0
   */
  byte getStructureVersion() {
    return structureVersion;
  }

  /**
   * Gets the issuer key reference.
   *
   * @return A copy of the issuer key reference (29 bytes).
   * @since 0.1.0
   */
  byte[] getIssuerKeyReference() {
    return issuerKeyReference.clone();
  }

  /**
   * Gets the issuer AID size.
   *
   * @return The issuer AID size (5-16).
   * @since 0.1.0
   */
  byte getIssuerAidSize() {
    return issuerAidSize;
  }

  /**
   * Gets the issuer AID value.
   *
   * @return A copy of the issuer AID value (16 bytes, padded).
   * @since 0.1.0
   */
  byte[] getIssuerAidValue() {
    return issuerAidValue.clone();
  }

  /**
   * Gets the issuer serial number.
   *
   * @return A copy of the issuer serial number (8 bytes).
   * @since 0.1.0
   */
  byte[] getIssuerSerialNumber() {
    return issuerSerialNumber.clone();
  }

  /**
   * Gets the issuer key ID.
   *
   * @return A copy of the issuer key ID (4 bytes).
   * @since 0.1.0
   */
  byte[] getIssuerKeyId() {
    return issuerKeyId.clone();
  }

  /**
   * Gets the card AID size.
   *
   * @return The card AID size (5-16).
   * @since 0.1.0
   */
  byte getCardAidSize() {
    return cardAidSize;
  }

  /**
   * Gets the card AID value.
   *
   * @return A copy of the card AID value (16 bytes, padded).
   * @since 0.1.0
   */
  byte[] getCardAidValue() {
    return cardAidValue.clone();
  }

  /**
   * Gets the card serial number.
   *
   * @return A copy of the card serial number (8 bytes).
   * @since 0.1.0
   */
  byte[] getCardSerialNumber() {
    return cardSerialNumber.clone();
  }

  /**
   * Gets the card index.
   *
   * @return A copy of the card index (4 bytes).
   * @since 0.1.0
   */
  byte[] getCardIndex() {
    return cardIndex.clone();
  }

  /**
   * Gets the signature.
   *
   * @return A copy of the signature (256 bytes).
   * @since 0.1.0
   */
  byte[] getSignature() {
    return signature.clone();
  }

  /**
   * Gets the start date from recoverable data.
   *
   * @return The start date as a LocalDate, or null if not set.
   * @since 0.1.0
   */
  LocalDate getStartDate() {
    return startDate;
  }

  /**
   * Gets the end date from recoverable data.
   *
   * @return The end date as a LocalDate, or null if not set.
   * @since 0.1.0
   */
  LocalDate getEndDate() {
    return endDate;
  }

  /**
   * Gets the card rights from recoverable data.
   *
   * @return The card rights byte.
   * @since 0.1.0
   */
  byte getCardRights() {
    return cardRights;
  }

  /**
   * Gets the card info from recoverable data.
   *
   * @return A copy of the card info (7 bytes).
   * @since 0.1.0
   */
  byte[] getCardInfo() {
    return cardInfo.clone();
  }

  /**
   * Gets the RFU field from recoverable data.
   *
   * @return A copy of the RFU field (18 bytes).
   * @since 0.1.0
   */
  byte[] getCardRfu() {
    return cardRfu.clone();
  }

  /**
   * Gets the ECC public key from recoverable data.
   *
   * @return A copy of the ECC public key (64 bytes).
   * @since 0.1.0
   */
  byte[] getEccPublicKey() {
    return eccPublicKey.clone();
  }

  /**
   * Gets the ECC RFU from recoverable data.
   *
   * @return A copy of the ECC RFU (124 bytes).
   * @since 0.1.0
   */
  byte[] getEccRfu() {
    return eccRfu.clone();
  }

  /**
   * Gets the certificate type as an enum.
   *
   * @return The certificate type.
   * @since 0.1.0
   */
  CertificateType getCertificateType() {
    return CertificateType.fromByte(certType);
  }

  /**
   * Serializes the recoverable data for ISO9796-2 signature (222 bytes).
   *
   * <p>This represents the data that will be embedded in the signature and can be recovered during
   * verification according to the ISO9796-2 scheme.
   *
   * @return A 222-byte array containing the recoverable data.
   * @since 0.1.0
   */
  byte[] getRecoverableDataForSigning() {
    byte[] data = new byte[CertificateConstants.RECOVERABLE_DATA_SIZE];
    int offset = 0;

    // KCertStartDate (4 bytes)
    if (startDate != null) {
      byte[] encodedStartDate =
          CertificateUtils.encodeDateBcd(
              startDate.getYear(), startDate.getMonthValue(), startDate.getDayOfMonth());
      System.arraycopy(encodedStartDate, 0, data, offset, CertificateConstants.DATE_SIZE);
    }
    offset += CertificateConstants.DATE_SIZE;

    // KCertEndDate (4 bytes)
    if (endDate != null) {
      byte[] encodedEndDate =
          CertificateUtils.encodeDateBcd(
              endDate.getYear(), endDate.getMonthValue(), endDate.getDayOfMonth());
      System.arraycopy(encodedEndDate, 0, data, offset, CertificateConstants.DATE_SIZE);
    }
    offset += CertificateConstants.DATE_SIZE;

    // KCertCardRights (1 byte)
    data[offset++] = cardRights;

    // KCertCardInfo (7 bytes)
    if (cardInfo != null) {
      System.arraycopy(cardInfo, 0, data, offset, CertificateConstants.CARD_STARTUP_INFO_SIZE);
    }
    offset += CertificateConstants.CARD_STARTUP_INFO_SIZE;

    // KCertCardRfu (18 bytes)
    System.arraycopy(cardRfu, 0, data, offset, CertificateConstants.CARD_RFU_SIZE);
    offset += CertificateConstants.CARD_RFU_SIZE;

    // KCertEccPublicKey (64 bytes)
    if (eccPublicKey != null) {
      System.arraycopy(eccPublicKey, 0, data, offset, CertificateConstants.ECC_PUBLIC_KEY_SIZE);
    }
    offset += CertificateConstants.ECC_PUBLIC_KEY_SIZE;

    // KCertEccRfu (124 bytes)
    System.arraycopy(eccRfu, 0, data, offset, CertificateConstants.ECC_RFU_SIZE);

    return data;
  }

  /**
   * Serializes the non-recoverable data for ISO9796-2 signature (60 bytes).
   *
   * <p>This represents the data that must be signed according to the Calypso Prime Legacy
   * specification.
   *
   * @return A 60-byte array containing the non-recoverable data to be signed.
   * @since 0.1.0
   */
  byte[] toBytesForSigning() {
    byte[] data = new byte[CertificateConstants.CARD_NON_RECOVERABLE_DATA_SIZE];
    int offset = 0;

    // KCertType (1 byte)
    data[offset++] = certType;

    // KCertStructureVersion (1 byte)
    data[offset++] = structureVersion;

    // KCertIssuerKeyReference (29 bytes)
    System.arraycopy(issuerKeyReference, 0, data, offset, CertificateConstants.KEY_REFERENCE_SIZE);
    offset += CertificateConstants.KEY_REFERENCE_SIZE;

    // KCertCardAidSize (1 byte)
    data[offset++] = cardAidSize;

    // KCertCardAidValue (16 bytes)
    System.arraycopy(cardAidValue, 0, data, offset, CertificateConstants.AID_VALUE_SIZE);
    offset += CertificateConstants.AID_VALUE_SIZE;

    // KCertCardSerialNumber (8 bytes)
    if (cardSerialNumber != null) {
      System.arraycopy(cardSerialNumber, 0, data, offset, CertificateConstants.SERIAL_NUMBER_SIZE);
    }
    offset += CertificateConstants.SERIAL_NUMBER_SIZE;

    // KCertCardIndex (4 bytes)
    System.arraycopy(cardIndex, 0, data, offset, CertificateConstants.CARD_INDEX_SIZE);

    return data;
  }

  /**
   * Serializes the complete certificate to bytes (with signature).
   *
   * <p>This represents the full 316-byte Card certificate according to the Calypso Prime Legacy
   * specification.
   *
   * @return A 316-byte array containing the complete certificate.
   * @since 0.1.0
   */
  byte[] toBytes() {
    byte[] serialized = new byte[CertificateConstants.CARD_CERTIFICATE_SIZE];
    int offset = 0;

    // Copy the non-recoverable data (60 bytes)
    byte[] dataForSigning = toBytesForSigning();
    System.arraycopy(
        dataForSigning, 0, serialized, offset, CertificateConstants.CARD_NON_RECOVERABLE_DATA_SIZE);
    offset += CertificateConstants.CARD_NON_RECOVERABLE_DATA_SIZE;

    // KCertSignature (256 bytes)
    System.arraycopy(signature, 0, serialized, offset, CertificateConstants.RSA_SIGNATURE_SIZE);

    return serialized;
  }

  /**
   * Creates a new builder instance.
   *
   * @return A new builder.
   * @since 0.1.0
   */
  static Builder builder() {
    return new Builder();
  }

  /**
   * Builder for {@link CardCertificate}.
   *
   * @since 0.1.0
   */
  static final class Builder {
    private byte certType;
    private byte structureVersion;
    private byte[] issuerKeyReference;
    private byte issuerAidSize;
    private byte[] issuerAidValue;
    private byte[] issuerSerialNumber;
    private byte[] issuerKeyId;
    private byte cardAidSize;
    private byte[] cardAidValue;
    private byte[] cardSerialNumber;
    private byte[] cardIndex;
    private byte[] signature;
    private byte[] startDate;
    private byte[] endDate;
    private byte cardRights;
    private byte[] cardInfo;
    private byte[] cardRfu;
    private byte[] eccPublicKey;
    private byte[] eccRfu;

    private Builder() {}

    Builder certType(byte certType) {
      this.certType = certType;
      return this;
    }

    Builder structureVersion(byte structureVersion) {
      this.structureVersion = structureVersion;
      return this;
    }

    Builder issuerKeyReference(byte[] issuerKeyReference) {
      this.issuerKeyReference = issuerKeyReference;
      return this;
    }

    Builder issuerAidSize(byte issuerAidSize) {
      this.issuerAidSize = issuerAidSize;
      return this;
    }

    Builder issuerAidValue(byte[] issuerAidValue) {
      this.issuerAidValue = issuerAidValue;
      return this;
    }

    Builder issuerSerialNumber(byte[] issuerSerialNumber) {
      this.issuerSerialNumber = issuerSerialNumber;
      return this;
    }

    Builder issuerKeyId(byte[] issuerKeyId) {
      this.issuerKeyId = issuerKeyId;
      return this;
    }

    Builder cardAidSize(byte cardAidSize) {
      this.cardAidSize = cardAidSize;
      return this;
    }

    Builder cardAidValue(byte[] cardAidValue) {
      this.cardAidValue = cardAidValue;
      return this;
    }

    Builder cardSerialNumber(byte[] cardSerialNumber) {
      this.cardSerialNumber = cardSerialNumber;
      return this;
    }

    Builder cardIndex(byte[] cardIndex) {
      this.cardIndex = cardIndex;
      return this;
    }

    Builder signature(byte[] signature) {
      this.signature = signature;
      return this;
    }

    Builder startDate(byte[] startDate) {
      this.startDate = startDate;
      return this;
    }

    Builder endDate(byte[] endDate) {
      this.endDate = endDate;
      return this;
    }

    Builder cardRights(byte cardRights) {
      this.cardRights = cardRights;
      return this;
    }

    Builder cardInfo(byte[] cardInfo) {
      this.cardInfo = cardInfo;
      return this;
    }

    Builder cardRfu(byte[] cardRfu) {
      this.cardRfu = cardRfu;
      return this;
    }

    Builder eccPublicKey(byte[] eccPublicKey) {
      this.eccPublicKey = eccPublicKey;
      return this;
    }

    Builder eccRfu(byte[] eccRfu) {
      this.eccRfu = eccRfu;
      return this;
    }

    CardCertificate build() {
      return new CardCertificate(this);
    }
  }
}
