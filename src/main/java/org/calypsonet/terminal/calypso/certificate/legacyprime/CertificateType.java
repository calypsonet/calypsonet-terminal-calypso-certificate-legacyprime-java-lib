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

import org.eclipse.keyple.core.util.HexUtil;

/**
 * Enumeration of certificate types in the Calypso Prime Legacy system.
 *
 * @since 0.1.0
 */
enum CertificateType {
  /** CA Certificate (0x90). */
  CA((byte) 0x90),

  /** Card Certificate (0x91). */
  CARD((byte) 0x91);

  private final byte value;

  /**
   * Constructor.
   *
   * @param value The byte value of the certificate type.
   */
  CertificateType(byte value) {
    this.value = value;
  }

  /**
   * Gets the byte value of this certificate type.
   *
   * @return The byte value.
   */
  byte getValue() {
    return value;
  }

  /**
   * Gets the certificate type from its byte value.
   *
   * @param value The byte value.
   * @return The corresponding certificate type.
   * @throws IllegalArgumentException if the value is not recognized.
   */
  static CertificateType fromByte(byte value) {
    for (CertificateType type : values()) {
      if (type.value == value) {
        return type;
      }
    }
    throw new IllegalArgumentException("Unknown certificate type: 0x" + HexUtil.toHex(value));
  }
}
