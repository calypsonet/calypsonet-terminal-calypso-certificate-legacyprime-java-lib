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
 * Enumeration of CA scope values in the Calypso Prime Legacy system.
 *
 * @since 0.1.0
 */
enum CaScope {
  /** Scope not specified (0x00). */
  NOT_SPECIFIED((byte) 0x00),

  /** Allowed only for development, tests, pilots, etc. (0x01). */
  DEVELOPMENT((byte) 0x01),

  /** No scope restriction (0xFF). */
  NOT_RESTRICTED((byte) 0xFF);

  private final byte value;

  /**
   * Constructor.
   *
   * @param value The byte value of the CA scope.
   */
  CaScope(byte value) {
    this.value = value;
  }

  /**
   * Gets the byte value of this CA scope.
   *
   * @return The byte value.
   */
  byte getValue() {
    return value;
  }

  /**
   * Gets the CA scope from its byte value.
   *
   * @param value The byte value.
   * @return The corresponding CA scope.
   * @throws IllegalArgumentException if the value is not recognized.
   */
  static CaScope fromByte(byte value) {
    for (CaScope scope : values()) {
      if (scope.value == value) {
        return scope;
      }
    }
    throw new IllegalArgumentException("Unsupported CaScope: 0x" + HexUtil.toHex(value));
  }
}
