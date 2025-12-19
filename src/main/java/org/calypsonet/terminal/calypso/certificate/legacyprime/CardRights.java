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
 * Value object representing Card rights in the Calypso Prime Legacy system.
 *
 * <p>Card rights are encoded in a single byte whose structure is defined by the Calypso Prime
 * Legacy specification.
 *
 * @since 0.1.0
 */
final class CardRights {
  private final byte value;

  /**
   * Creates a new Card rights instance.
   *
   * @param value The byte value representing the rights.
   */
  private CardRights(byte value) {
    this.value = value;
  }

  /**
   * Creates a Card rights instance from its byte representation.
   *
   * @param value The byte value containing the rights.
   * @return The Card rights instance.
   */
  static CardRights fromByte(byte value) {
    return new CardRights(value);
  }

  /**
   * Converts this Card rights to its byte representation.
   *
   * @return The byte representation.
   */
  byte toByte() {
    return value;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    CardRights that = (CardRights) o;
    return value == that.value;
  }

  @Override
  public int hashCode() {
    return value;
  }

  @Override
  public String toString() {
    return "CardRights{value=0x" + String.format("%02X", value) + '}';
  }
}
