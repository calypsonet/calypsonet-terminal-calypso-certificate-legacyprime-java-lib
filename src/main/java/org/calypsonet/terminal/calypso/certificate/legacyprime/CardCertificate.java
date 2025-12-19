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
import org.eclipse.keyple.core.util.Assert;

/**
 * Internal class representing a Card Certificate with all its fields.
 *
 * <p>This class stores all fields from a 316-byte Card certificate according to the Calypso Prime
 * Legacy specification. It follows an auto-contained pattern with strong object-oriented
 * encapsulation.
 *
 * @since 0.1.0
 */
final class CardCertificate {
  private final CertificateType certType;
  private final byte structureVersion;
  private final KeyReference issuerKeyReference;
  private final Aid cardAid;
  private final byte[] cardSerialNumber;
  private final byte[] cardIndex;
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
    this.issuerKeyReference = builder.issuerKeyReference;
    this.cardAid = builder.cardAid;
    this.cardSerialNumber = builder.cardSerialNumber;
    this.cardIndex = builder.cardIndex;
    this.startDate = builder.startDate;
    this.endDate = builder.endDate;
    this.cardRights = builder.cardRights;
    this.cardInfo = builder.cardInfo;
    this.cardRfu = builder.cardRfu;
    this.eccPublicKey = builder.eccPublicKey;
    this.eccRfu = builder.eccRfu;
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
    System.arraycopy(cardInfo, 0, data, offset, CertificateConstants.CARD_STARTUP_INFO_SIZE);
    offset += CertificateConstants.CARD_STARTUP_INFO_SIZE;

    // KCertCardRfu (18 bytes)
    System.arraycopy(cardRfu, 0, data, offset, CertificateConstants.CARD_RFU_SIZE);
    offset += CertificateConstants.CARD_RFU_SIZE;

    // KCertEccPublicKey (64 bytes)
    System.arraycopy(eccPublicKey, 0, data, offset, CertificateConstants.ECC_PUBLIC_KEY_SIZE);
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
    data[offset++] = certType.getValue();

    // KCertStructureVersion (1 byte)
    data[offset++] = structureVersion;

    // KCertIssuerKeyReference (29 bytes)
    byte[] issuerKeyRefBytes = issuerKeyReference.toBytes();
    System.arraycopy(issuerKeyRefBytes, 0, data, offset, CertificateConstants.KEY_REFERENCE_SIZE);
    offset += CertificateConstants.KEY_REFERENCE_SIZE;

    // KCertCardAidSize (1 byte)
    data[offset++] = cardAid.getSize();

    // KCertCardAidValue (16 bytes)
    System.arraycopy(
        cardAid.getPaddedValue(), 0, data, offset, CertificateConstants.AID_VALUE_SIZE);
    offset += CertificateConstants.AID_VALUE_SIZE;

    // KCertCardSerialNumber (8 bytes)
    System.arraycopy(cardSerialNumber, 0, data, offset, CertificateConstants.SERIAL_NUMBER_SIZE);
    offset += CertificateConstants.SERIAL_NUMBER_SIZE;

    // KCertCardIndex (4 bytes)
    System.arraycopy(cardIndex, 0, data, offset, CertificateConstants.CARD_INDEX_SIZE);

    return data;
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
    private CertificateType certType;
    private byte structureVersion;
    private KeyReference issuerKeyReference;
    private Aid cardAid;
    private byte[] cardSerialNumber;
    private byte[] cardIndex;
    private LocalDate startDate;
    private LocalDate endDate;
    private byte cardRights;
    private byte[] cardInfo;
    private byte[] cardRfu;
    private byte[] eccPublicKey;
    private byte[] eccRfu;

    private Builder() {}

    Builder certType(byte certType) {
      this.certType = CertificateType.fromByte(certType);
      return this;
    }

    Builder structureVersion(byte structureVersion) {
      this.structureVersion = structureVersion;
      return this;
    }

    Builder issuerKeyReference(byte[] issuerKeyReference) {
      this.issuerKeyReference = KeyReference.fromBytes(issuerKeyReference);
      return this;
    }

    Builder cardAidUnpaddedValue(byte[] cardAidAidUnpaddedValue) {
      this.cardAid = Aid.fromUnpaddedValue(cardAidAidUnpaddedValue);
      Assert.getInstance().isTrue(!cardAid.isRfu(), "cardAid must be defined");
      return this;
    }

    Builder cardSerialNumber(byte[] cardSerialNumber) {
      Assert.getInstance()
          .notNull(cardSerialNumber, "cardSerialNumber")
          .isEqual(
              cardSerialNumber.length,
              CertificateConstants.SERIAL_NUMBER_SIZE,
              "cardSerialNumber.length");
      this.cardSerialNumber = cardSerialNumber.clone();
      return this;
    }

    Builder cardIndex(byte[] cardIndex) {
      Assert.getInstance()
          .notNull(cardIndex, "cardIndex")
          .isEqual(cardIndex.length, CertificateConstants.CARD_INDEX_SIZE, "cardIndex.length");
      this.cardIndex = cardIndex.clone();
      return this;
    }

    Builder startDate(byte[] startDate) {
      this.startDate = CertificateUtils.decodeDateBcd(startDate);
      return this;
    }

    Builder endDate(byte[] endDate) {
      this.endDate = CertificateUtils.decodeDateBcd(endDate);
      return this;
    }

    Builder cardRights(byte cardRights) {
      this.cardRights = cardRights;
      return this;
    }

    Builder cardInfo(byte[] cardInfo) {
      Assert.getInstance()
          .notNull(cardInfo, "cardInfo")
          .isEqual(cardInfo.length, CertificateConstants.CARD_STARTUP_INFO_SIZE, "cardInfo.length");
      this.cardInfo = cardInfo.clone();
      return this;
    }

    Builder cardRfu(byte[] cardRfu) {
      Assert.getInstance()
          .notNull(cardRfu, "cardRfu")
          .isEqual(cardRfu.length, CertificateConstants.CARD_RFU_SIZE, "cardRfu.length");
      this.cardRfu = cardRfu.clone();
      return this;
    }

    Builder eccPublicKey(byte[] eccPublicKey) {
      Assert.getInstance()
          .notNull(eccPublicKey, "eccPublicKey")
          .isEqual(
              eccPublicKey.length, CertificateConstants.ECC_PUBLIC_KEY_SIZE, "eccPublicKey.length");
      this.eccPublicKey = eccPublicKey.clone();
      return this;
    }

    Builder eccRfu(byte[] eccRfu) {
      Assert.getInstance()
          .notNull(eccRfu, "eccRfu")
          .isEqual(eccRfu.length, CertificateConstants.ECC_RFU_SIZE, "eccRfu.length");
      this.eccRfu = eccRfu.clone();
      return this;
    }

    CardCertificate build() {
      // Validate required fields
      Assert.getInstance()
          .notNull(certType, "certType")
          .notNull(issuerKeyReference, "issuerKeyReference")
          .notNull(cardAid, "cardAid")
          .notNull(cardSerialNumber, "cardSerialNumber")
          .notNull(cardIndex, "cardIndex")
          .notNull(cardInfo, "cardInfo")
          .notNull(cardRfu, "cardRfu")
          .notNull(eccPublicKey, "eccPublicKey")
          .notNull(eccRfu, "eccRfu");

      return new CardCertificate(this);
    }
  }
}
