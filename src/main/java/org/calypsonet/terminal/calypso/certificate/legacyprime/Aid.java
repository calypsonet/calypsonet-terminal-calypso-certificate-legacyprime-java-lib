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
 * Internal class representing an Application Identifier (AID) with validation rules.
 *
 * <p>An AID is an identifier that must be:
 *
 * <ul>
 *   <li>Between 5 and 16 bytes in length
 *   <li>Not composed entirely of zero bytes
 *   <li>Padded with zeros to 16 bytes when serialized
 * </ul>
 *
 * @since 0.1.0
 */
final class Aid {
  private final byte[] value;

  /**
   * Creates a new AID instance.
   *
   * @param value The AID value (5-16 bytes, not all zeros).
   * @throws IllegalArgumentException if the AID is invalid.
   * @since 0.1.0
   */
  private Aid(byte[] value) {
    validateAid(value);
    this.value = value.clone();
  }

  /**
   * Gets the AID size.
   *
   * @return The AID size (5-16).
   * @since 0.1.0
   */
  byte getSize() {
    return (byte) value.length;
  }

  /**
   * Gets the actual AID value (unpadded).
   *
   * @return A copy of the actual AID value.
   * @since 0.1.0
   */
  byte[] getValue() {
    return value.clone();
  }

  /**
   * Gets the padded AID value (16 bytes).
   *
   * @return A 16-byte array containing the AID value padded with zeros.
   * @since 0.1.0
   */
  byte[] getPaddedValue() {
    byte[] padded = new byte[CertificateConstants.AID_VALUE_SIZE];
    System.arraycopy(value, 0, padded, 0, value.length);
    return padded;
  }

  /**
   * Checks if this AID matches another AID according to the specified operating mode.
   *
   * @param other The other AID to compare with.
   * @param operatingMode The operating mode to use for matching.
   * @return true if the AIDs match according to the truncation rules.
   * @since 0.1.0
   */
  boolean matches(Aid other, OperatingMode operatingMode) {
    if (other == null) {
      return false;
    }

    if (operatingMode.isTruncationAllowed()) {
      // Truncation allowed: check if one AID starts with the other
      if (this.value.length <= other.value.length) {
        // Check if other starts with this
        for (int i = 0; i < this.value.length; i++) {
          if (this.value[i] != other.value[i]) {
            return false;
          }
        }
        return true;
      } else {
        // Check if this starts with other
        for (int i = 0; i < other.value.length; i++) {
          if (this.value[i] != other.value[i]) {
            return false;
          }
        }
        return true;
      }
    } else {
      // Truncation forbidden: exact match required
      return Arrays.equals(this.value, other.value);
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
    bytes[0] = getSize();
    System.arraycopy(value, 0, bytes, 1, value.length);
    return bytes;
  }

  /**
   * Parses an AID from its byte array representation (size + padded value).
   *
   * @param aidBytes The 17-byte array containing AID size and padded value.
   * @return The parsed AID.
   * @throws IllegalArgumentException if the AID data is invalid.
   * @since 0.1.0
   */
  static Aid fromBytes(byte[] aidBytes) {
    if (aidBytes == null || aidBytes.length != (1 + CertificateConstants.AID_VALUE_SIZE)) {
      throw new IllegalArgumentException(
          "AID bytes must be "
              + (1 + CertificateConstants.AID_VALUE_SIZE)
              + " bytes (size + value), got "
              + (aidBytes == null ? "null" : aidBytes.length));
    }

    byte aidSize = aidBytes[0];
    if (aidSize < CertificateConstants.AID_MIN_LENGTH
        || aidSize > CertificateConstants.AID_MAX_LENGTH) {
      throw new IllegalArgumentException(
          "AID size must be between "
              + CertificateConstants.AID_MIN_LENGTH
              + " and "
              + CertificateConstants.AID_MAX_LENGTH
              + ", got "
              + aidSize);
    }

    byte[] aidValue = new byte[aidSize];
    System.arraycopy(aidBytes, 1, aidValue, 0, aidSize);

    return new Aid(aidValue);
  }

  /**
   * Creates an AID from an unpadded byte array.
   *
   * @param aidValue The AID value (5-16 bytes).
   * @return The created AID.
   * @throws IllegalArgumentException if the AID is invalid.
   * @since 0.1.0
   */
  static Aid fromValue(byte[] aidValue) {
    return new Aid(aidValue);
  }

  /**
   * Validates an AID value.
   *
   * @param aidValue The AID value to validate.
   * @throws IllegalArgumentException if the AID is invalid.
   */
  private static void validateAid(byte[] aidValue) {
    if (aidValue == null) {
      throw new IllegalArgumentException("AID value cannot be null");
    }

    if (aidValue.length < CertificateConstants.AID_MIN_LENGTH
        || aidValue.length > CertificateConstants.AID_MAX_LENGTH) {
      throw new IllegalArgumentException(
          "AID length must be between "
              + CertificateConstants.AID_MIN_LENGTH
              + " and "
              + CertificateConstants.AID_MAX_LENGTH
              + ", got "
              + aidValue.length);
    }

    // Check if AID contains only zero bytes
    boolean allZeros = true;
    for (byte b : aidValue) {
      if (b != 0) {
        allZeros = false;
        break;
      }
    }

    if (allZeros) {
      throw new IllegalArgumentException("AID cannot contain only zero bytes");
    }
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    Aid aid = (Aid) o;
    return Arrays.equals(value, aid.value);
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(value);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder("Aid{");
    for (int i = 0; i < value.length; i++) {
      if (i > 0) sb.append(" ");
      sb.append(String.format("%02X", value[i]));
    }
    sb.append("}");
    return sb.toString();
  }
}
