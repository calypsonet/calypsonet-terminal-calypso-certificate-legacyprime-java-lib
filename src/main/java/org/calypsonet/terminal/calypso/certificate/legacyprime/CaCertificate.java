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

/**
 * Internal class representing a CA Certificate with all its fields.
 *
 * <p>This class stores all fields from a 384-byte CA certificate according to the Calypso Prime
 * Legacy specification.
 *
 * @since 0.1.0
 */
final class CaCertificate {
  private final byte certType;
  private final byte structureVersion;
  private final byte[] issuerKeyReference;
  private final byte[] caTargetKeyReference;
  private final byte caAidSize;
  private final byte[] caAidValue;
  private final byte[] caSerialNumber;
  private final byte[] caKeyId;
  private final byte[] startDate;
  private final byte[] caRfu1;
  private final byte caRights;
  private final byte caScope;
  private final byte[] endDate;
  private final byte caTargetAidSize;
  private final byte[] caTargetAidValue;
  private final byte caOperatingMode;
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
    this.certType = builder.certType;
    this.structureVersion = builder.structureVersion;
    this.issuerKeyReference =
        builder.issuerKeyReference != null ? builder.issuerKeyReference.clone() : null;
    this.caTargetKeyReference =
        builder.caTargetKeyReference != null ? builder.caTargetKeyReference.clone() : null;
    this.caAidSize = builder.caAidSize;
    this.caAidValue = builder.caAidValue != null ? builder.caAidValue.clone() : null;
    this.caSerialNumber = builder.caSerialNumber != null ? builder.caSerialNumber.clone() : null;
    this.caKeyId = builder.caKeyId != null ? builder.caKeyId.clone() : null;
    this.startDate = builder.startDate != null ? builder.startDate.clone() : null;
    this.caRfu1 = builder.caRfu1 != null ? builder.caRfu1.clone() : null;
    this.caRights = builder.caRights;
    this.caScope = builder.caScope;
    this.endDate = builder.endDate != null ? builder.endDate.clone() : null;
    this.caTargetAidSize = builder.caTargetAidSize;
    this.caTargetAidValue =
        builder.caTargetAidValue != null ? builder.caTargetAidValue.clone() : null;
    this.caOperatingMode = builder.caOperatingMode;
    this.caRfu2 = builder.caRfu2 != null ? builder.caRfu2.clone() : null;
    this.publicKeyHeader = builder.publicKeyHeader != null ? builder.publicKeyHeader.clone() : null;
    this.signature = builder.signature != null ? builder.signature.clone() : null;
    this.rsaPublicKey = builder.rsaPublicKey;
  }

  /**
   * Gets the certificate type.
   *
   * @return The certificate type (0x90).
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
   * @return A copy of the start date (4 bytes, YYYYMMDD in BCD).
   * @since 0.1.0
   */
  byte[] getStartDate() {
    return startDate.clone();
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
   * Gets the CA rights.
   *
   * @return The CA rights byte.
   * @since 0.1.0
   */
  byte getCaRights() {
    return caRights;
  }

  /**
   * Gets the CA scope.
   *
   * @return The CA scope (0x00, 0x01, or 0xFF).
   * @since 0.1.0
   */
  byte getCaScope() {
    return caScope;
  }

  /**
   * Gets the end date.
   *
   * @return A copy of the end date (4 bytes, YYYYMMDD in BCD).
   * @since 0.1.0
   */
  byte[] getEndDate() {
    return endDate.clone();
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
   * Gets the operating mode.
   *
   * @return The operating mode (0 = truncation forbidden, 1 = truncation allowed).
   * @since 0.1.0
   */
  byte getCaOperatingMode() {
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
    byte[] data = new byte[128];
    int offset = 0;

    // KCertType (1 byte)
    data[offset++] = certType;

    // KCertStructureVersion (1 byte)
    data[offset++] = structureVersion;

    // KCertIssuerKeyReference (29 bytes)
    System.arraycopy(issuerKeyReference, 0, data, offset, 29);
    offset += 29;

    // KCertCaTargetKeyReference (29 bytes)
    System.arraycopy(caTargetKeyReference, 0, data, offset, 29);
    offset += 29;

    // KCertStartDate (4 bytes)
    if (startDate != null) {
      System.arraycopy(startDate, 0, data, offset, 4);
    }
    offset += 4;

    // KCertCaRfu1 (4 bytes)
    System.arraycopy(caRfu1, 0, data, offset, 4);
    offset += 4;

    // KCertCaRights (1 byte)
    data[offset++] = caRights;

    // KCertCaScope (1 byte)
    data[offset++] = caScope;

    // KCertEndDate (4 bytes)
    if (endDate != null) {
      System.arraycopy(endDate, 0, data, offset, 4);
    }
    offset += 4;

    // KCertCaTargetAidSize (1 byte)
    data[offset++] = caTargetAidSize;

    // KCertCaTargetAidValue (16 bytes)
    System.arraycopy(caTargetAidValue, 0, data, offset, 16);
    offset += 16;

    // KCertCaOperatingMode (1 byte)
    data[offset++] = caOperatingMode;

    // KCertCaRfu2 (2 bytes)
    System.arraycopy(caRfu2, 0, data, offset, 2);
    offset += 2;

    // KCertPublicKeyHeader (34 bytes)
    System.arraycopy(publicKeyHeader, 0, data, offset, 34);

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
    byte[] serialized = new byte[384];
    int offset = 0;

    // Copy the data to be signed (128 bytes)
    byte[] dataForSigning = toBytesForSigning();
    System.arraycopy(dataForSigning, 0, serialized, offset, 128);
    offset += 128;

    // KCertSignature (256 bytes)
    System.arraycopy(signature, 0, serialized, offset, 256);

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
