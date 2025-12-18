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
 * Value object representing CA rights in the Calypso Prime Legacy system.
 *
 * <p>CA rights are encoded in a single byte with the following structure:
 *
 * <ul>
 *   <li>Bits b7-b4: Reserved for future use (must be 0)
 *   <li>Bits b3-b2: Card certificate signing right
 *   <li>Bits b1-b0: CA certificate signing right
 * </ul>
 *
 * @since 0.1.0
 */
final class CaRights {
  static final byte CA_RIGHTS_NOT_SPECIFIED = (byte) 0x00;

  private final CertRight cardCertRight;
  private final CertRight caCertRight;

  /**
   * Creates a new CA rights instance.
   *
   * @param cardCertRight The right to sign card certificates.
   * @param caCertRight The right to sign CA certificates.
   */
  CaRights(CertRight cardCertRight, CertRight caCertRight) {
    this.cardCertRight = cardCertRight;
    this.caCertRight = caCertRight;
  }

  /**
   * Gets the right to sign card certificates.
   *
   * @return The card certificate signing right.
   */
  CertRight getCardCertRight() {
    return cardCertRight;
  }

  /**
   * Gets the right to sign CA certificates.
   *
   * @return The CA certificate signing right.
   */
  CertRight getCaCertRight() {
    return caCertRight;
  }

  /**
   * Converts this CA rights to its byte representation.
   *
   * @return The byte representation.
   */
  byte toByte() {
    return (byte)
        ((cardCertRight.getValue() << CertificateConstants.SHIFT_CARD_CERT_RIGHT)
            | caCertRight.getValue());
  }

  /**
   * Creates a CA rights instance from its byte representation.
   *
   * @param rightsValue The byte value containing the rights.
   * @return The CA rights instance.
   * @throws IllegalArgumentException if bits b7-b4 are not 0, or if any right value is RFU.
   */
  static CaRights fromByte(byte rightsValue) {
    // Check that bits b7-b4 are 0 (RFU)
    if ((rightsValue & CertificateConstants.MASK_HIGH_NIBBLE) != 0) {
      throw new IllegalArgumentException("CA rights bits b7-b4 must be 0 (RFU)");
    }

    // Extract card certificate right (bits b3-b2)
    int cardCertRightValue =
        (rightsValue >> CertificateConstants.SHIFT_CARD_CERT_RIGHT)
            & CertificateConstants.MASK_TWO_BITS;

    // Extract CA certificate right (bits b1-b0)
    int caCertRightValue = rightsValue & CertificateConstants.MASK_TWO_BITS;

    // Convert to enums (will throw if RFU values)
    CertRight cardCertRight = CertRight.fromValue(cardCertRightValue);
    CertRight caCertRight = CertRight.fromValue(caCertRightValue);

    return new CaRights(cardCertRight, caCertRight);
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    CaRights caRights = (CaRights) o;
    return cardCertRight == caRights.cardCertRight && caCertRight == caRights.caCertRight;
  }

  @Override
  public int hashCode() {
    return 31 * cardCertRight.hashCode() + caCertRight.hashCode();
  }

  @Override
  public String toString() {
    return "CaRights{cardCert=" + cardCertRight + ", caCert=" + caCertRight + '}';
  }
}
