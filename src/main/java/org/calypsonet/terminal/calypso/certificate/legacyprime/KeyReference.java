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

import java.util.Arrays;

/**
 * Internal class representing a Key Reference with all its fields.
 *
 * <p>A Key Reference is a 29-byte structure containing:
 *
 * <ul>
 *   <li>AID Size (1 byte): Size of the AID value (5-16)
 *   <li>AID Value (16 bytes): Application identifier, padded with zeros
 *   <li>Serial Number (8 bytes): SAM or card serial number
 *   <li>Key ID (4 bytes): Key identifier (often RFU = 00000000h)
 * </ul>
 *
 * @since 0.1.0
 */
final class KeyReference {
  private final byte aidSize;
  private final byte[] aidValue;
  private final byte[] serialNumber;
  private final byte[] keyId;

  /**
   * Creates a new key reference instance.
   *
   * @param aidSize The AID size (5-16).
   * @param aidValue The AID value (16 bytes, padded with zeros).
   * @param serialNumber The serial number (8 bytes).
   * @param keyId The key ID (4 bytes).
   * @since 0.1.0
   */
  private KeyReference(byte aidSize, byte[] aidValue, byte[] serialNumber, byte[] keyId) {
    this.aidSize = aidSize;
    this.aidValue = aidValue != null ? aidValue.clone() : null;
    this.serialNumber = serialNumber != null ? serialNumber.clone() : null;
    this.keyId = keyId != null ? keyId.clone() : null;
  }

  /**
   * Gets the AID size.
   *
   * @return The AID size (5-16).
   * @since 0.1.0
   */
  byte getAidSize() {
    return aidSize;
  }

  /**
   * Gets the AID value.
   *
   * @return A copy of the AID value (16 bytes, padded).
   * @since 0.1.0
   */
  byte[] getAidValue() {
    return aidValue.clone();
  }

  /**
   * Gets the serial number.
   *
   * @return A copy of the serial number (8 bytes).
   * @since 0.1.0
   */
  byte[] getSerialNumber() {
    return serialNumber.clone();
  }

  /**
   * Gets the key ID.
   *
   * @return A copy of the key ID (4 bytes).
   * @since 0.1.0
   */
  byte[] getKeyId() {
    return keyId.clone();
  }

  /**
   * Serializes the key reference to bytes.
   *
   * @return A 29-byte array containing the key reference.
   * @since 0.1.0
   */
  byte[] toBytes() {
    byte[] bytes = new byte[CertificateConstants.KEY_REFERENCE_SIZE];
    int offset = 0;

    // AID Size (1 byte)
    bytes[offset++] = aidSize;

    // AID Value (16 bytes)
    System.arraycopy(aidValue, 0, bytes, offset, CertificateConstants.AID_VALUE_SIZE);
    offset += CertificateConstants.AID_VALUE_SIZE;

    // Serial Number (8 bytes)
    System.arraycopy(serialNumber, 0, bytes, offset, CertificateConstants.SERIAL_NUMBER_SIZE);
    offset += CertificateConstants.SERIAL_NUMBER_SIZE;

    // Key ID (4 bytes)
    System.arraycopy(keyId, 0, bytes, offset, CertificateConstants.KEY_ID_SIZE);

    return bytes;
  }

  /**
   * Parses a key reference from its byte array representation.
   *
   * @param keyReference The 29-byte key reference to parse.
   * @return The parsed key reference.
   * @throws IllegalArgumentException if the key reference data is invalid.
   * @since 0.1.0
   */
  static KeyReference fromBytes(byte[] keyReference) {
    if (keyReference == null || keyReference.length != CertificateConstants.KEY_REFERENCE_SIZE) {
      throw new IllegalArgumentException(
          "Key reference must be "
              + CertificateConstants.KEY_REFERENCE_SIZE
              + " bytes, got "
              + (keyReference == null ? "null" : keyReference.length));
    }

    int offset = 0;

    // AID Size (1 byte)
    byte aidSize = keyReference[offset++];

    // AID Value (16 bytes)
    byte[] aidValue = new byte[CertificateConstants.AID_VALUE_SIZE];
    System.arraycopy(keyReference, offset, aidValue, 0, CertificateConstants.AID_VALUE_SIZE);
    offset += CertificateConstants.AID_VALUE_SIZE;

    // Serial Number (8 bytes)
    byte[] serialNumber = new byte[CertificateConstants.SERIAL_NUMBER_SIZE];
    System.arraycopy(
        keyReference, offset, serialNumber, 0, CertificateConstants.SERIAL_NUMBER_SIZE);
    offset += CertificateConstants.SERIAL_NUMBER_SIZE;

    // Key ID (4 bytes)
    byte[] keyId = new byte[CertificateConstants.KEY_ID_SIZE];
    System.arraycopy(keyReference, offset, keyId, 0, CertificateConstants.KEY_ID_SIZE);

    return new KeyReference(aidSize, aidValue, serialNumber, keyId);
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

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    KeyReference that = (KeyReference) o;
    return aidSize == that.aidSize
        && Arrays.equals(aidValue, that.aidValue)
        && Arrays.equals(serialNumber, that.serialNumber)
        && Arrays.equals(keyId, that.keyId);
  }

  @Override
  public int hashCode() {
    int result = aidSize;
    result = 31 * result + Arrays.hashCode(aidValue);
    result = 31 * result + Arrays.hashCode(serialNumber);
    result = 31 * result + Arrays.hashCode(keyId);
    return result;
  }

  /**
   * Builder for {@link KeyReference}.
   *
   * @since 0.1.0
   */
  static final class Builder {
    private byte aidSize;
    private byte[] aidValue;
    private byte[] serialNumber;
    private byte[] keyId;

    private Builder() {}

    /**
     * Sets the AID size.
     *
     * @param aidSize The AID size (5-16).
     * @return This builder instance.
     * @since 0.1.0
     */
    Builder aidSize(byte aidSize) {
      this.aidSize = aidSize;
      return this;
    }

    /**
     * Sets the AID value.
     *
     * @param aidValue The AID value (16 bytes, padded).
     * @return This builder instance.
     * @since 0.1.0
     */
    Builder aidValue(byte[] aidValue) {
      this.aidValue = aidValue;
      return this;
    }

    /**
     * Sets the serial number.
     *
     * @param serialNumber The serial number (8 bytes).
     * @return This builder instance.
     * @since 0.1.0
     */
    Builder serialNumber(byte[] serialNumber) {
      this.serialNumber = serialNumber;
      return this;
    }

    /**
     * Sets the key ID.
     *
     * @param keyId The key ID (4 bytes).
     * @return This builder instance.
     * @since 0.1.0
     */
    Builder keyId(byte[] keyId) {
      this.keyId = keyId;
      return this;
    }

    /**
     * Builds the key reference instance.
     *
     * @return The key reference.
     * @since 0.1.0
     */
    KeyReference build() {
      return new KeyReference(aidSize, aidValue, serialNumber, keyId);
    }
  }
}
