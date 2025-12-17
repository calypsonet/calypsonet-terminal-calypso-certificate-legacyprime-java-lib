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

/**
 * Internal class representing a CA Certificate with all its fields.
 *
 * <p>This class stores all fields from a 384-byte CA certificate according to the Calypso Prime
 * Legacy specification.
 *
 * @since 0.1.0
 */
final class CaCertificate {
  private final CertificateType certType;
  private final byte structureVersion;
  private final byte[] issuerKeyReference;
  private final byte[] caTargetKeyReference;
  private final byte caAidSize;
  private final byte[] caAidValue;
  private final byte[] caSerialNumber;
  private final byte[] caKeyId;
  private final LocalDate startDate;
  private final byte[] caRfu1;
  private final CaRights caRights;
  private final CaScope caScope;
  private final LocalDate endDate;
  private final byte caTargetAidSize;
  private final byte[] caTargetAidValue;
  private final OperatingMode caOperatingMode;
  private final byte[] caRfu2;
  private final byte[] publicKeyHeader;
  private final byte[] signature;
  private final RSAPublicKey rsaPublicKey;

  /**
   * Creates a new CA certificate instance.
   *
   * @param builder The builder containing all certificate fields.
   * @since 0.1.0
   */
  private CaCertificate(Builder builder) {
    this.certType = CertificateType.fromByte(builder.certType);
    this.structureVersion = builder.structureVersion;
    this.issuerKeyReference =
        builder.issuerKeyReference != null ? builder.issuerKeyReference.clone() : null;
    this.caTargetKeyReference =
        builder.caTargetKeyReference != null ? builder.caTargetKeyReference.clone() : null;
    this.caAidSize = builder.caAidSize;
    this.caAidValue = builder.caAidValue != null ? builder.caAidValue.clone() : null;
    this.caSerialNumber = builder.caSerialNumber != null ? builder.caSerialNumber.clone() : null;
    this.caKeyId = builder.caKeyId != null ? builder.caKeyId.clone() : null;
    this.startDate =
        builder.startDate != null ? CertificateUtils.decodeDateBcd(builder.startDate) : null;
    this.caRfu1 = builder.caRfu1 != null ? builder.caRfu1.clone() : null;
    this.caRights = CaRights.fromByte(builder.caRights);
    this.caScope = CaScope.fromByte(builder.caScope);
    this.endDate = builder.endDate != null ? CertificateUtils.decodeDateBcd(builder.endDate) : null;
    this.caTargetAidSize = builder.caTargetAidSize;
    this.caTargetAidValue =
        builder.caTargetAidValue != null ? builder.caTargetAidValue.clone() : null;
    this.caOperatingMode = OperatingMode.fromByte(builder.caOperatingMode);
    this.caRfu2 = builder.caRfu2 != null ? builder.caRfu2.clone() : null;
    this.publicKeyHeader = builder.publicKeyHeader != null ? builder.publicKeyHeader.clone() : null;
    this.signature = builder.signature != null ? builder.signature.clone() : null;
    this.rsaPublicKey = builder.rsaPublicKey;
  }

  /**
   * Retrieves the certificate type associated with this CA certificate.
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
    return issuerKeyReference.clone();
  }

  /**
   * Gets the CA target key reference.
   *
   * @return A copy of the CA target key reference (29 bytes).
   * @since 0.1.0
   */
  byte[] getCaTargetKeyReference() {
    return caTargetKeyReference.clone();
  }

  /**
   * Gets the CA AID size.
   *
   * @return The CA AID size (5-16).
   * @since 0.1.0
   */
  byte getCaAidSize() {
    return caAidSize;
  }

  /**
   * Gets the CA AID value.
   *
   * @return A copy of the CA AID value (16 bytes, padded).
   * @since 0.1.0
   */
  byte[] getCaAidValue() {
    return caAidValue.clone();
  }

  /**
   * Gets the CA serial number.
   *
   * @return A copy of the CA serial number (8 bytes).
   * @since 0.1.0
   */
  byte[] getCaSerialNumber() {
    return caSerialNumber.clone();
  }

  /**
   * Gets the CA key ID.
   *
   * @return A copy of the CA key ID (4 bytes).
   * @since 0.1.0
   */
  byte[] getCaKeyId() {
    return caKeyId.clone();
  }

  /**
   * Gets the start date.
   *
   * @return The start date as a LocalDate, or null if not set.
   * @since 0.1.0
   */
  LocalDate getStartDate() {
    return startDate;
  }

  /**
   * Gets the RFU field 1.
   *
   * @return A copy of the RFU field 1 (4 bytes).
   * @since 0.1.0
   */
  byte[] getCaRfu1() {
    return caRfu1.clone();
  }

  /**
   * Retrieves the CA rights associated with this certificate.
   *
   * @return The CA rights object representing permissions and capabilities related to card and CA
   *     certificate signing.
   * @since 0.1.0
   */
  CaRights getCaRights() {
    return caRights;
  }

  /**
   * Retrieves the CA scope associated with this certificate.
   *
   * @return The CA scope as a {@code CaScope} enum value.
   * @since 0.1.0
   */
  CaScope getCaScope() {
    return caScope;
  }

  /**
   * Gets the end date.
   *
   * @return The end date as a LocalDate, or null if not set.
   * @since 0.1.0
   */
  LocalDate getEndDate() {
    return endDate;
  }

  /**
   * Gets the target AID size.
   *
   * @return The target AID size (5-16).
   * @since 0.1.0
   */
  byte getCaTargetAidSize() {
    return caTargetAidSize;
  }

  /**
   * Gets the target AID value.
   *
   * @return A copy of the target AID value (16 bytes, padded).
   * @since 0.1.0
   */
  byte[] getCaTargetAidValue() {
    return caTargetAidValue.clone();
  }

  /**
   * Gets the CA operating mode.
   *
   * @return The CA operating mode indicating whether truncation is allowed or forbidden.
   * @since 0.1.0
   */
  OperatingMode getCaOperatingMode() {
    return caOperatingMode;
  }

  /**
   * Gets the RFU field 2.
   *
   * @return A copy of the RFU field 2 (2 bytes).
   * @since 0.1.0
   */
  byte[] getCaRfu2() {
    return caRfu2.clone();
  }

  /**
   * Gets the public key header.
   *
   * @return A copy of the public key header (34 bytes).
   * @since 0.1.0
   */
  byte[] getPublicKeyHeader() {
    return publicKeyHeader.clone();
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
   * Gets the RSA public key.
   *
   * <p>The RSA public key is reconstructed from the certificate data during parsing.
   *
   * @return The RSA public key, or null if not set.
   * @since 0.1.0
   */
  RSAPublicKey getRsaPublicKey() {
    return rsaPublicKey;
  }

  /**
   * Serializes the certificate fields to bytes (without signature).
   *
   * <p>This represents the data that must be signed according to the Calypso Prime Legacy
   * specification (128 bytes from KCertType to KCertPublicKeyHeader).
   *
   * @return A 128-byte array containing the certificate data to be signed.
   * @since 0.1.0
   */
  byte[] toBytesForSigning() {
    byte[] data = new byte[CertificateConstants.CA_DATA_FOR_SIGNING_SIZE];
    int offset = 0;

    // KCertType (1 byte)
    data[offset++] = certType.getValue();

    // KCertStructureVersion (1 byte)
    data[offset++] = structureVersion;

    // KCertIssuerKeyReference (29 bytes)
    System.arraycopy(issuerKeyReference, 0, data, offset, CertificateConstants.KEY_REFERENCE_SIZE);
    offset += CertificateConstants.KEY_REFERENCE_SIZE;

    // KCertCaTargetKeyReference (29 bytes)
    System.arraycopy(
        caTargetKeyReference, 0, data, offset, CertificateConstants.KEY_REFERENCE_SIZE);
    offset += CertificateConstants.KEY_REFERENCE_SIZE;

    // KCertStartDate (4 bytes)
    if (startDate != null) {
      byte[] encodedStartDate =
          CertificateUtils.encodeDateBcd(
              startDate.getYear(), startDate.getMonthValue(), startDate.getDayOfMonth());
      System.arraycopy(encodedStartDate, 0, data, offset, CertificateConstants.DATE_SIZE);
    }
    offset += CertificateConstants.DATE_SIZE;

    // KCertCaRfu1 (4 bytes)
    System.arraycopy(caRfu1, 0, data, offset, CertificateConstants.CA_RFU1_SIZE);
    offset += CertificateConstants.CA_RFU1_SIZE;

    // KCertCaRights (1 byte)
    data[offset++] = caRights.toByte();

    // KCertCaScope (1 byte)
    data[offset++] = caScope.getValue();

    // KCertEndDate (4 bytes)
    if (endDate != null) {
      byte[] encodedEndDate =
          CertificateUtils.encodeDateBcd(
              endDate.getYear(), endDate.getMonthValue(), endDate.getDayOfMonth());
      System.arraycopy(encodedEndDate, 0, data, offset, CertificateConstants.DATE_SIZE);
    }
    offset += CertificateConstants.DATE_SIZE;

    // KCertCaTargetAidSize (1 byte)
    data[offset++] = caTargetAidSize;

    // KCertCaTargetAidValue (16 bytes)
    System.arraycopy(caTargetAidValue, 0, data, offset, CertificateConstants.AID_VALUE_SIZE);
    offset += CertificateConstants.AID_VALUE_SIZE;

    // KCertCaOperatingMode (1 byte)
    data[offset++] = caOperatingMode.getValue();

    // KCertCaRfu2 (2 bytes)
    System.arraycopy(caRfu2, 0, data, offset, CertificateConstants.CA_RFU2_SIZE);
    offset += CertificateConstants.CA_RFU2_SIZE;

    // KCertPublicKeyHeader (34 bytes)
    System.arraycopy(publicKeyHeader, 0, data, offset, CertificateConstants.PUBLIC_KEY_HEADER_SIZE);

    return data;
  }

  /**
   * Serializes the complete certificate to bytes (with signature).
   *
   * <p>This represents the full 384-byte CA certificate according to the Calypso Prime Legacy
   * specification.
   *
   * @return A 384-byte array containing the complete certificate.
   * @since 0.1.0
   */
  byte[] toBytes() {
    byte[] serialized = new byte[CertificateConstants.CA_CERTIFICATE_SIZE];
    int offset = 0;

    // Copy the data to be signed (128 bytes)
    byte[] dataForSigning = toBytesForSigning();
    System.arraycopy(
        dataForSigning, 0, serialized, offset, CertificateConstants.CA_DATA_FOR_SIGNING_SIZE);
    offset += CertificateConstants.CA_DATA_FOR_SIGNING_SIZE;

    // KCertSignature (256 bytes)
    System.arraycopy(signature, 0, serialized, offset, CertificateConstants.RSA_SIGNATURE_SIZE);

    return serialized;
  }

  /**
   * Parses a CA certificate from its byte array representation.
   *
   * <p>This method deserializes a 384-byte CA certificate according to the Calypso Prime Legacy
   * specification and reconstructs all certificate fields including the RSA public key.
   *
   * @param caCertificate The 384-byte certificate to parse.
   * @return The parsed CA certificate.
   * @throws IllegalArgumentException if the certificate data is invalid.
   * @since 0.1.0
   */
  static CaCertificate fromBytes(byte[] caCertificate, RSAPublicKey issuerPublicKey) {
    if (caCertificate == null || caCertificate.length != CertificateConstants.CA_CERTIFICATE_SIZE) {
      throw new IllegalArgumentException(
          "CA certificate must be "
              + CertificateConstants.CA_CERTIFICATE_SIZE
              + " bytes, got "
              + (caCertificate == null ? "null" : caCertificate.length));
    }

    int offset = 0;

    // KCertType (1 byte)
    byte certType = caCertificate[offset++];

    // KCertStructureVersion (1 byte)
    byte structureVersion = caCertificate[offset++];

    // KCertIssuerKeyReference (29 bytes)
    byte[] issuerKeyReference = new byte[CertificateConstants.KEY_REFERENCE_SIZE];
    System.arraycopy(
        caCertificate, offset, issuerKeyReference, 0, CertificateConstants.KEY_REFERENCE_SIZE);
    offset += CertificateConstants.KEY_REFERENCE_SIZE;

    // KCertCaTargetKeyReference (29 bytes)
    byte[] caTargetKeyReference = new byte[CertificateConstants.KEY_REFERENCE_SIZE];
    System.arraycopy(
        caCertificate, offset, caTargetKeyReference, 0, CertificateConstants.KEY_REFERENCE_SIZE);
    offset += CertificateConstants.KEY_REFERENCE_SIZE;

    // Extract fields from caTargetKeyReference
    byte caAidSize = caTargetKeyReference[CertificateConstants.KEY_REF_OFFSET_AID_SIZE];
    byte[] caAidValue = new byte[CertificateConstants.AID_VALUE_SIZE];
    System.arraycopy(
        caTargetKeyReference,
        CertificateConstants.KEY_REF_OFFSET_AID_VALUE,
        caAidValue,
        0,
        CertificateConstants.AID_VALUE_SIZE);
    byte[] caSerialNumber = new byte[CertificateConstants.SERIAL_NUMBER_SIZE];
    System.arraycopy(
        caTargetKeyReference,
        CertificateConstants.KEY_REF_OFFSET_SERIAL_NUMBER,
        caSerialNumber,
        0,
        CertificateConstants.SERIAL_NUMBER_SIZE);
    byte[] caKeyId = new byte[CertificateConstants.KEY_ID_SIZE];
    System.arraycopy(
        caTargetKeyReference,
        CertificateConstants.KEY_REF_OFFSET_KEY_ID,
        caKeyId,
        0,
        CertificateConstants.KEY_ID_SIZE);

    // KCertStartDate (4 bytes)
    byte[] startDate = new byte[CertificateConstants.DATE_SIZE];
    System.arraycopy(caCertificate, offset, startDate, 0, CertificateConstants.DATE_SIZE);
    offset += CertificateConstants.DATE_SIZE;

    // KCertCaRfu1 (4 bytes)
    byte[] caRfu1 = new byte[CertificateConstants.CA_RFU1_SIZE];
    System.arraycopy(caCertificate, offset, caRfu1, 0, CertificateConstants.CA_RFU1_SIZE);
    offset += CertificateConstants.CA_RFU1_SIZE;

    // KCertCaRights (1 byte)
    byte caRights = caCertificate[offset++];

    // KCertCaScope (1 byte)
    byte caScope = caCertificate[offset++];

    // KCertEndDate (4 bytes)
    byte[] endDate = new byte[CertificateConstants.DATE_SIZE];
    System.arraycopy(caCertificate, offset, endDate, 0, CertificateConstants.DATE_SIZE);
    offset += CertificateConstants.DATE_SIZE;

    // KCertCaTargetAidSize (1 byte)
    byte caTargetAidSize = caCertificate[offset++];

    // KCertCaTargetAidValue (16 bytes)
    byte[] caTargetAidValue = new byte[CertificateConstants.AID_VALUE_SIZE];
    System.arraycopy(
        caCertificate, offset, caTargetAidValue, 0, CertificateConstants.AID_VALUE_SIZE);
    offset += CertificateConstants.AID_VALUE_SIZE;

    // KCertCaOperatingMode (1 byte)
    byte caOperatingMode = caCertificate[offset++];

    // KCertCaRfu2 (2 bytes)
    byte[] caRfu2 = new byte[CertificateConstants.CA_RFU2_SIZE];
    System.arraycopy(caCertificate, offset, caRfu2, 0, CertificateConstants.CA_RFU2_SIZE);
    offset += CertificateConstants.CA_RFU2_SIZE;

    // KCertPublicKeyHeader (34 bytes)
    byte[] caPublicKeyHeader = new byte[CertificateConstants.PUBLIC_KEY_HEADER_SIZE];
    System.arraycopy(
        caCertificate, offset, caPublicKeyHeader, 0, CertificateConstants.PUBLIC_KEY_HEADER_SIZE);
    offset += CertificateConstants.PUBLIC_KEY_HEADER_SIZE;

    // KCertSignature (256 bytes)
    byte[] signature = new byte[CertificateConstants.RSA_SIGNATURE_SIZE];
    System.arraycopy(caCertificate, offset, signature, 0, CertificateConstants.RSA_SIGNATURE_SIZE);

    // Reconstruct the RSA public key from the public key header and signature
    RSAPublicKey rsaPublicKey =
        CertificateUtils.checkCaCertificateSignatureAndRecoverRsaPublicKey(
            caCertificate, caPublicKeyHeader, issuerPublicKey);

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
        .publicKeyHeader(caPublicKeyHeader)
        .signature(signature)
        .rsaPublicKey(rsaPublicKey)
        .build();
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
   * Builder for {@link CaCertificate}.
   *
   * @since 0.1.0
   */
  static final class Builder {
    private byte certType;
    private byte structureVersion;
    private byte[] issuerKeyReference;
    private byte[] caTargetKeyReference;
    private byte caAidSize;
    private byte[] caAidValue;
    private byte[] caSerialNumber;
    private byte[] caKeyId;
    private byte[] startDate;
    private byte[] caRfu1;
    private byte caRights;
    private byte caScope;
    private byte[] endDate;
    private byte caTargetAidSize;
    private byte[] caTargetAidValue;
    private byte caOperatingMode;
    private byte[] caRfu2;
    private byte[] publicKeyHeader;
    private byte[] signature;
    private RSAPublicKey rsaPublicKey;

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

    Builder caTargetKeyReference(byte[] caTargetKeyReference) {
      this.caTargetKeyReference = caTargetKeyReference;
      return this;
    }

    Builder caAidSize(byte caAidSize) {
      this.caAidSize = caAidSize;
      return this;
    }

    Builder caAidValue(byte[] caAidValue) {
      this.caAidValue = caAidValue;
      return this;
    }

    Builder caSerialNumber(byte[] caSerialNumber) {
      this.caSerialNumber = caSerialNumber;
      return this;
    }

    Builder caKeyId(byte[] caKeyId) {
      this.caKeyId = caKeyId;
      return this;
    }

    Builder startDate(byte[] startDate) {
      this.startDate = startDate;
      return this;
    }

    Builder caRfu1(byte[] caRfu1) {
      this.caRfu1 = caRfu1;
      return this;
    }

    Builder caRights(byte caRights) {
      this.caRights = caRights;
      return this;
    }

    Builder caScope(byte caScope) {
      this.caScope = caScope;
      return this;
    }

    Builder endDate(byte[] endDate) {
      this.endDate = endDate;
      return this;
    }

    Builder caTargetAidSize(byte caTargetAidSize) {
      this.caTargetAidSize = caTargetAidSize;
      return this;
    }

    Builder caTargetAidValue(byte[] caTargetAidValue) {
      this.caTargetAidValue = caTargetAidValue;
      return this;
    }

    Builder caOperatingMode(byte caOperatingMode) {
      this.caOperatingMode = caOperatingMode;
      return this;
    }

    Builder caRfu2(byte[] caRfu2) {
      this.caRfu2 = caRfu2;
      return this;
    }

    Builder publicKeyHeader(byte[] publicKeyHeader) {
      this.publicKeyHeader = publicKeyHeader;
      return this;
    }

    Builder signature(byte[] signature) {
      this.signature = signature;
      return this;
    }

    /**
     * Sets the RSA public key.
     *
     * @param rsaPublicKey The RSA public key.
     * @return This builder instance.
     * @since 0.1.0
     */
    Builder rsaPublicKey(RSAPublicKey rsaPublicKey) {
      this.rsaPublicKey = rsaPublicKey;
      return this;
    }

    CaCertificate build() {
      return new CaCertificate(this);
    }
  }
}
