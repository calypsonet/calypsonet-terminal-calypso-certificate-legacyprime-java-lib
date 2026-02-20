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
 * Enumeration of certificate signing rights in the Calypso Prime Legacy system.
 *
 * <p>This represents the 2-bit values used in the CA Rights field.
 *
 * @since 0.1.0
 */
enum CertRight {
  /** Certificate signing right not specified (0b00). */
  NOT_SPECIFIED(0b00),

  /** Shall not sign certificates (0b01). */
  SHALL_NOT_SIGN(0b01),

  /** May sign certificates (0b10). */
  MAY_SIGN(0b10);

  // Note: 0b11 is RFU (Reserved for Future Use) and is intentionally omitted

  private final int value;

  /**
   * Constructor.
   *
   * @param value The 2-bit value of the certificate right.
   */
  CertRight(int value) {
    this.value = value;
  }

  /**
   * Gets the 2-bit value of this certificate right.
   *
   * @return The 2-bit value.
   */
  int getValue() {
    return value;
  }

  /**
   * Gets the certificate right from its 2-bit value.
   *
   * @param value The 2-bit value (0-3).
   * @return The corresponding certificate right.
   * @throws IllegalArgumentException if the value is not recognized or is RFU (0b11).
   */
  static CertRight fromValue(int value) {
    if (value == 0b11) {
      throw new IllegalArgumentException("Certificate right value 0b11 is reserved for future use");
    }
    for (CertRight right : values()) {
      if (right.value == value) {
        return right;
      }
    }
    throw new IllegalArgumentException("Unsupported CertRight: " + value);
  }
}
