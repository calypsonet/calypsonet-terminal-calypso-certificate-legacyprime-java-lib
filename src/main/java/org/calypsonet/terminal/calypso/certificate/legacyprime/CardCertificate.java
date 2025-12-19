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
  private final byte[] signature;
  // Recoverable data from signature
  private final LocalDate startDate;
  private final LocalDate endDate;
  private final CardRights cardRights;
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
    this.signature = builder.signature;
    this.startDate = builder.startDate;
    this.endDate = builder.endDate;
    this.cardRights = builder.cardRights;
    this.cardInfo = builder.cardInfo;
    this.cardRfu = builder.cardRfu;
    this.eccPublicKey = builder.eccPublicKey;
    this.eccRfu = builder.eccRfu;
  }

  /**
   * Retrieves the certificate type associated with this Card certificate.
   *
   * @return The certificate type as a {@code CertificateType} enum value.
   * @since 0.1.0
   */
  CertificateType getCertType() {
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
    return issuerKeyReference.toBytes();
  }

  /**
   * Gets the issuer key reference as an object.
   *
   * @return The issuer key reference.
   * @since 0.1.0
   */
  KeyReference getIssuerKeyReferenceObject() {
    return issuerKeyReference;
  }

  /**
   * Gets the issuer AID size from the issuer key reference.
   *
   * @return The issuer AID size (5-16).
   * @since 0.1.0
   */
  byte getIssuerAidSize() {
    return issuerKeyReference.getAidSize();
  }

  /**
   * Gets the issuer AID value from the issuer key reference.
   *
   * @return A copy of the issuer AID value (16 bytes, padded).
   * @since 0.1.0
   */
  byte[] getIssuerAidValue() {
    return issuerKeyReference.getAidValue();
  }

  /**
   * Gets the issuer serial number from the issuer key reference.
   *
   * @return A copy of the issuer serial number (8 bytes).
   * @since 0.1.0
   */
  byte[] getIssuerSerialNumber() {
    return issuerKeyReference.getSerialNumber();
  }

  /**
   * Gets the issuer key ID from the issuer key reference.
   *
   * @return A copy of the issuer key ID (4 bytes).
   * @since 0.1.0
   */
  byte[] getIssuerKeyId() {
    return issuerKeyReference.getKeyId();
  }

  /**
   * Gets the card AID object.
   *
   * @return The card AID.
   * @since 0.1.0
   */
  Aid getCardAid() {
    return cardAid;
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
   * Retrieves the card rights associated with this certificate.
   *
   * @return The card rights object representing the permissions.
   * @since 0.1.0
   */
  CardRights getCardRights() {
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
    data[offset++] = cardRights.toByte();

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
    private CertificateType certType;
    private byte structureVersion;
    private KeyReference issuerKeyReference;
    private Aid cardAid;
    private byte[] cardSerialNumber;
    private byte[] cardIndex;
    private byte[] signature;
    private LocalDate startDate;
    private LocalDate endDate;
    private CardRights cardRights;
    private byte[] cardInfo;
    private byte[] cardRfu;
    private byte[] eccPublicKey;
    private byte[] eccRfu;

    private Builder() {}

    Builder certType(CertificateType certType) {
      Assert.getInstance().notNull(certType, "certType");
      this.certType = certType;
      return this;
    }

    Builder certType(byte certType) {
      this.certType = CertificateType.fromByte(certType);
      return this;
    }

    Builder structureVersion(byte structureVersion) {
      this.structureVersion = structureVersion;
      return this;
    }

    Builder issuerKeyReference(KeyReference issuerKeyReference) {
      Assert.getInstance().notNull(issuerKeyReference, "issuerKeyReference");
      this.issuerKeyReference = issuerKeyReference;
      return this;
    }

    Builder issuerKeyReference(byte[] issuerKeyReference) {
      Assert.getInstance().notNull(issuerKeyReference, "issuerKeyReference");

      // If the reference is shorter than 29 bytes, it's a short reference
      // We need to pad it to create a full KeyReference
      if (issuerKeyReference.length < CertificateConstants.KEY_REFERENCE_SIZE) {
        byte[] paddedReference = new byte[CertificateConstants.KEY_REFERENCE_SIZE];
        System.arraycopy(issuerKeyReference, 0, paddedReference, 0, issuerKeyReference.length);
        this.issuerKeyReference = KeyReference.fromBytes(paddedReference);
      } else {
        Assert.getInstance()
            .isEqual(
                issuerKeyReference.length,
                CertificateConstants.KEY_REFERENCE_SIZE,
                "issuerKeyReference.length");
        this.issuerKeyReference = KeyReference.fromBytes(issuerKeyReference);
      }
      return this;
    }

    Builder cardAid(Aid cardAid) {
      Assert.getInstance().notNull(cardAid, "cardAid");
      this.cardAid = cardAid;
      return this;
    }

    Builder cardSerialNumber(byte[] cardSerialNumber) {
      if (cardSerialNumber != null) {
        Assert.getInstance()
            .isEqual(
                cardSerialNumber.length,
                CertificateConstants.SERIAL_NUMBER_SIZE,
                "cardSerialNumber.length");
        this.cardSerialNumber = cardSerialNumber.clone();
      } else {
        this.cardSerialNumber = null;
      }
      return this;
    }

    Builder cardIndex(byte[] cardIndex) {
      Assert.getInstance()
          .notNull(cardIndex, "cardIndex")
          .isEqual(cardIndex.length, CertificateConstants.CARD_INDEX_SIZE, "cardIndex.length");
      this.cardIndex = cardIndex.clone();
      return this;
    }

    Builder signature(byte[] signature) {
      Assert.getInstance()
          .notNull(signature, "signature")
          .isEqual(signature.length, CertificateConstants.RSA_SIGNATURE_SIZE, "signature.length");
      this.signature = signature.clone();
      return this;
    }

    Builder startDate(LocalDate startDate) {
      this.startDate = startDate;
      return this;
    }

    Builder startDate(byte[] startDate) {
      if (startDate != null) {
        Assert.getInstance()
            .isEqual(startDate.length, CertificateConstants.DATE_SIZE, "startDate.length");
        this.startDate = CertificateUtils.decodeDateBcd(startDate);
      } else {
        this.startDate = null;
      }
      return this;
    }

    Builder endDate(LocalDate endDate) {
      this.endDate = endDate;
      return this;
    }

    Builder endDate(byte[] endDate) {
      if (endDate != null) {
        Assert.getInstance()
            .isEqual(endDate.length, CertificateConstants.DATE_SIZE, "endDate.length");
        this.endDate = CertificateUtils.decodeDateBcd(endDate);
      } else {
        this.endDate = null;
      }
      return this;
    }

    Builder cardRights(CardRights cardRights) {
      Assert.getInstance().notNull(cardRights, "cardRights");
      this.cardRights = cardRights;
      return this;
    }

    Builder cardRights(byte cardRights) {
      this.cardRights = CardRights.fromByte(cardRights);
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
      // Validate required fields (startDate, endDate, and cardSerialNumber are optional)
      Assert.getInstance()
          .notNull(certType, "certType")
          .notNull(issuerKeyReference, "issuerKeyReference")
          .notNull(cardAid, "cardAid")
          .notNull(cardIndex, "cardIndex")
          .notNull(signature, "signature")
          .notNull(cardRights, "cardRights")
          .notNull(cardInfo, "cardInfo")
          .notNull(cardRfu, "cardRfu")
          .notNull(eccPublicKey, "eccPublicKey")
          .notNull(eccRfu, "eccRfu");

      return new CardCertificate(this);
    }
  }
}
