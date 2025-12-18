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

/**
 * Internal class representing an Application Identifier (AID) with validation rules.
 *
 * <p>An AID is composed of:
 *
 * <ul>
 *   <li>Size: Between 5 and 16 bytes (or FFh for RFU)
 *   <li>Value: 16 bytes (padded with zeros if the actual AID is shorter)
 *   <li>Not composed entirely of zero bytes (unless size is FFh)
 * </ul>
 *
 * @since 0.1.0
 */
final class Aid {
  static final byte AID_SIZE_RFU = (byte) 0xFF;

  private final byte size;
  private final byte[] value;

  /**
   * Creates a new AID instance.
   *
   * @param size The AID size (5-16).
   * @param value The AID value (16 bytes, padded).
   * @since 0.1.0
   */
  private Aid(byte size, byte[] value) {
    this.size = size;
    this.value = value.clone();
  }

  /**
   * Gets the AID size.
   *
   * @return The AID size (5-16).
   * @since 0.1.0
   */
  byte getSize() {
    return size;
  }

  /**
   * Gets the padded AID value (16 bytes).
   *
   * @return A copy of the 16-byte padded AID value.
   * @since 0.1.0
   */
  byte[] getPaddedValue() {
    return value.clone();
  }

  /**
   * Gets the actual AID value (unpadded).
   *
   * @return A copy of the actual AID value (unpadded to size bytes). For RFU AIDs, returns all 16
   *     bytes.
   * @since 0.1.0
   */
  byte[] getUnpaddedValue() {
    if (isRfu()) {
      // For RFU, return all 16 bytes (all zeros)
      return value.clone();
    }
    byte[] unpadded = new byte[size];
    System.arraycopy(value, 0, unpadded, 0, size);
    return unpadded;
  }

  /**
   * Checks if this AID is an RFU (Reserved for Future Use) AID.
   *
   * @return true if this is an RFU AID (size = FFh), false otherwise.
   * @since 0.1.0
   */
  boolean isRfu() {
    return size == (byte) 0xFF;
  }

  /**
   * Checks if this AID matches the issuer AID according to the specified issuer operating mode.
   *
   * @param issuerAid The issuer AID to compare with.
   * @param issuerOperatingMode The operating mode to use for matching.
   * @return true if the AIDs match, according to the truncation rules.
   * @since 0.1.0
   */
  boolean matches(Aid issuerAid, OperatingMode issuerOperatingMode) {
    if (issuerAid == null) {
      return false;
    }

    if (issuerOperatingMode.isTruncationAllowed()) {
      // Truncation allowed: this AID must start with issuer AID and be at least as long
      if (this.size < issuerAid.size) {
        // This AID is shorter than issuerAid, cannot start with it
        return false;
      }
      // Check if this starts with issuerAid (compare first issuerAid.size bytes)
      for (int i = 0; i < issuerAid.size; i++) {
        if (this.value[i] != issuerAid.value[i]) {
          return false;
        }
      }
      return true;
    } else {
      // Truncation forbidden: exact match required (same size and same value bytes)
      if (this.size != issuerAid.size) {
        return false;
      }
      for (int i = 0; i < this.size; i++) {
        if (this.value[i] != issuerAid.value[i]) {
          return false;
        }
      }
      return true;
    }
  }

  /**
   * Serializes the AID to a 17-byte array (size + padded value).
   *
   * @return A 17-byte array containing the AID size and padded value.
   * @since 0.1.0
   */
  byte[] toBytes() {
    byte[] bytes = new byte[1 + CertificateConstants.AID_VALUE_SIZE];
    bytes[0] = size;
    System.arraycopy(value, 0, bytes, 1, CertificateConstants.AID_VALUE_SIZE);
    return bytes;
  }

  /**
   * Parses an AID from its components (size and padded value).
   *
   * @param aidSize The AID size (5-16, or FFh for RFU).
   * @param aidValue The padded AID value (16 bytes).
   * @return The parsed AID.
   * @throws IllegalArgumentException if the AID data is invalid.
   * @since 0.1.0
   */
  static Aid fromBytes(byte aidSize, byte[] aidValue) {
    if (aidValue == null || aidValue.length != CertificateConstants.AID_VALUE_SIZE) {
      throw new IllegalArgumentException(
          "AID value must be "
              + CertificateConstants.AID_VALUE_SIZE
              + " bytes, got "
              + (aidValue == null ? "null" : aidValue.length));
    }

    // Handle RFU case: size = FFh means no specific AID
    if (aidSize == (byte) 0xFF) {
      // Validate that AID value is all zeros (RFU requirement)
      for (byte b : aidValue) {
        if (b != 0) {
          throw new IllegalArgumentException(
              "When AID size is FFh (RFU), AID value must contain only zero bytes");
        }
      }
    } else {

      if (aidSize < CertificateConstants.AID_MIN_LENGTH
          || aidSize > CertificateConstants.AID_MAX_LENGTH) {
        throw new IllegalArgumentException(
            "AID size must be between "
                + CertificateConstants.AID_MIN_LENGTH
                + " and "
                + CertificateConstants.AID_MAX_LENGTH
                + " or FFh (RFU), got "
                + aidSize);
      }

      // Validate that the significant bytes are not all zeros
      boolean allZeros = true;
      for (int i = 0; i < aidSize; i++) {
        if (aidValue[i] != 0) {
          allZeros = false;
          break;
        }
      }
      if (allZeros) {
        throw new IllegalArgumentException("AID cannot contain only zero bytes");
      }
    }
    return new Aid(aidSize, aidValue);
  }

  /**
   * Creates an AID from an unpadded byte array.
   *
   * @param unpaddedValue The AID value (5-16 bytes, unpadded).
   * @return The created AID.
   * @throws IllegalArgumentException if the AID is invalid.
   * @since 0.1.0
   */
  static Aid fromUnpaddedValue(byte[] unpaddedValue) {
    if (unpaddedValue == null) {
      throw new IllegalArgumentException("AID value cannot be null");
    }

    if (unpaddedValue.length < CertificateConstants.AID_MIN_LENGTH
        || unpaddedValue.length > CertificateConstants.AID_MAX_LENGTH) {
      throw new IllegalArgumentException(
          "AID length must be between "
              + CertificateConstants.AID_MIN_LENGTH
              + " and "
              + CertificateConstants.AID_MAX_LENGTH
              + ", got "
              + unpaddedValue.length);
    }

    // Check if AID contains only zero bytes
    boolean allZeros = true;
    for (byte b : unpaddedValue) {
      if (b != 0) {
        allZeros = false;
        break;
      }
    }
    if (allZeros) {
      throw new IllegalArgumentException("AID cannot contain only zero bytes");
    }

    byte aidSize = (byte) unpaddedValue.length;
    byte[] paddedValue = new byte[CertificateConstants.AID_VALUE_SIZE];
    System.arraycopy(unpaddedValue, 0, paddedValue, 0, unpaddedValue.length);
    // The remaining bytes are already zero (default initialization)

    return new Aid(aidSize, paddedValue);
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    Aid aid = (Aid) o;
    if (this.size != aid.size) return false;
    // For RFU, compare all 16 bytes; otherwise compare only the significant bytes (up to size)
    int compareLength = isRfu() ? CertificateConstants.AID_VALUE_SIZE : size;
    for (int i = 0; i < compareLength; i++) {
      if (this.value[i] != aid.value[i]) {
        return false;
      }
    }
    return true;
  }

  @Override
  public int hashCode() {
    int result = size;
    // For RFU, hash all 16 bytes; otherwise hash only the significant bytes (up to size)
    int hashLength = isRfu() ? CertificateConstants.AID_VALUE_SIZE : size;
    for (int i = 0; i < hashLength; i++) {
      result = 31 * result + value[i];
    }
    return result;
  }

  @Override
  public String toString() {
    if (isRfu()) {
      return "Aid{RFU}";
    }
    StringBuilder sb = new StringBuilder("Aid{");
    // Display only the significant bytes (up to size)
    for (int i = 0; i < size; i++) {
      if (i > 0) sb.append(" ");
      sb.append(String.format("%02X", value[i]));
    }
    sb.append("}");
    return sb.toString();
  }
}
