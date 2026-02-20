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
 * Enumeration of AID truncation modes in the Calypso Prime Legacy system.
 *
 * <p>This corresponds to bit b0 of the CA Operating Mode field.
 *
 * @since 0.1.0
 */
enum OperatingMode {
  /** Truncation is forbidden (bit b0 = 0). */
  TRUNCATION_FORBIDDEN((byte) 0),

  /** Truncation is allowed (bit b0 = 1). */
  TRUNCATION_ALLOWED((byte) 1);

  private final byte value;

  /**
   * Constructor.
   *
   * @param value The byte value of the truncation mode.
   */
  OperatingMode(byte value) {
    this.value = value;
  }

  /**
   * Gets the byte value of this truncation mode.
   *
   * @return The byte value.
   */
  byte getValue() {
    return value;
  }

  /**
   * Checks if truncation is allowed.
   *
   * @return true if truncation is allowed, false otherwise.
   */
  boolean isTruncationAllowed() {
    return this == TRUNCATION_ALLOWED;
  }

  /**
   * Gets the truncation mode from its byte value.
   *
   * @param value The byte value (bit b0).
   * @return The corresponding truncation mode.
   * @throws IllegalArgumentException if the value is not 0 or 1.
   */
  static OperatingMode fromByte(byte value) {
    for (OperatingMode mode : values()) {
      if (mode.value == value) {
        return mode;
      }
    }
    throw new IllegalArgumentException("Unsupported OperatingMode: " + value);
  }
}
