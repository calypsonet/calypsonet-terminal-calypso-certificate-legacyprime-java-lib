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
 * Constants for Calypso Prime Legacy Certificate operations.
 *
 * <p>This class centralizes all magic numbers and constant values used throughout the certificate
 * generation, parsing, and validation processes according to the Calypso Prime Legacy
 * specification.
 *
 * @since 0.1.0
 */
final class CertificateConstants {

  // ==================== Certificate Types ====================

  /** Certificate type for CA certificates (0x90). */
  static final byte CERT_TYPE_CA = (byte) 0x90;

  /** Certificate type for Card certificates (0x91). */
  static final byte CERT_TYPE_CARD = (byte) 0x91;

  // ==================== Structure Versions ====================

  /** Certificate structure version (0x01). */
  static final byte STRUCTURE_VERSION = (byte) 0x01;

  // ==================== Certificate Sizes (bytes) ====================

  /** Total size of a CA certificate in bytes (384). */
  static final int CA_CERTIFICATE_SIZE = 384;

  /** Total size of a Card certificate in bytes (316). */
  static final int CARD_CERTIFICATE_SIZE = 316;

  /** Size of data to be signed for CA certificates in bytes (128). */
  static final int CA_DATA_FOR_SIGNING_SIZE = 128;

  /** Size of non-recoverable data for Card certificates in bytes (60). */
  static final int CARD_NON_RECOVERABLE_DATA_SIZE = 60;

  /** Size of recoverable data for certificates in bytes (222). */
  static final int RECOVERABLE_DATA_SIZE = 222;

  // ==================== RSA Cryptography ====================

  /** RSA signature size in bytes (256). */
  static final int RSA_SIGNATURE_SIZE = 256;

  /** RSA public key modulus size in bytes (256). */
  static final int RSA_MODULUS_SIZE = 256;

  /** RSA public key modulus size in bits (2048). */
  static final int RSA_MODULUS_BIT_LENGTH = 2048;

  /** RSA public exponent value (65537 = 0x10001). */
  static final int RSA_PUBLIC_EXPONENT = 65537;

  /** Public key header size in bytes (34). */
  static final int PUBLIC_KEY_HEADER_SIZE = 34;

  /** Size of modulus bytes encoded in signature (222). */
  static final int RSA_MODULUS_IN_SIGNATURE_SIZE = 222;

  /** Key algorithm name for RSA. */
  static final String KEY_ALGORITHM_RSA = "RSA";

  /** RSA transformation string for raw RSA operations. */
  static final String RSA_TRANSFORMATION = "RSA/ECB/NoPadding";

  // ==================== ECC Cryptography ====================

  /** ECC public key size in bytes (64). */
  static final int ECC_PUBLIC_KEY_SIZE = 64;

  /** ECC RFU (Reserved for Future Use) field size in bytes (124). */
  static final int ECC_RFU_SIZE = 124;

  // ==================== Field Sizes (bytes) ====================

  /** Key reference size in bytes (29). */
  static final int KEY_REFERENCE_SIZE = 29;

  /** AID value size in bytes, padded (16). */
  static final int AID_VALUE_SIZE = 16;

  /** Serial number size in bytes (8). */
  static final int SERIAL_NUMBER_SIZE = 8;

  /** Key ID size in bytes (4). */
  static final int KEY_ID_SIZE = 4;

  /** Card index size in bytes (4). */
  static final int CARD_INDEX_SIZE = 4;

  /** Date size in bytes, BCD encoded (4). */
  static final int DATE_SIZE = 4;

  /** Card startup info size in bytes (7). */
  static final int CARD_STARTUP_INFO_SIZE = 7;

  /** Card RFU (Reserved for Future Use) field size in bytes (18). */
  static final int CARD_RFU_SIZE = 18;

  /** CA RFU1 field size in bytes (4). */
  static final int CA_RFU1_SIZE = 4;

  /** CA RFU2 field size in bytes (2). */
  static final int CA_RFU2_SIZE = 2;

  // ==================== AID Constraints ====================

  /** Minimum AID length in bytes (5). */
  static final int AID_MIN_LENGTH = 5;

  /** Maximum AID length in bytes (16). */
  static final int AID_MAX_LENGTH = 16;

  // ==================== CA Scope Values ====================

  /** CA scope value: not specified (0x00). */
  static final byte CA_SCOPE_NOT_SPECIFIED = (byte) 0x00;

  /** CA scope value: specific scope (0x01). */
  static final byte CA_SCOPE_SPECIFIC = (byte) 0x01;

  /** CA scope value: universal scope (0xFF). */
  static final byte CA_SCOPE_UNIVERSAL = (byte) 0xFF;

  // ==================== Certificate Rights ====================

  /** Certificate right: not specified (0b00). */
  static final int CERT_RIGHT_NOT_SPECIFIED = 0x00;

  /** Certificate right: shall not sign (0b01). */
  static final int CERT_RIGHT_SHALL_NOT_SIGN = 0x01;

  /** Certificate right: may sign (0b10). */
  static final int CERT_RIGHT_MAY_SIGN = 0x02;

  /** Certificate right: reserved for future use (0b11). */
  static final int CERT_RIGHT_RFU = 0x03;

  // ==================== Bit Masks and Shifts ====================

  /** Bit mask for high nibble, bits 7-4 (0xF0). */
  static final int MASK_HIGH_NIBBLE = 0xF0;

  /** Bit mask for 2 low bits, bits 1-0 (0x03). */
  static final int MASK_TWO_BITS = 0x03;

  /** Bit shift for card certificate rights in CA rights byte (2 bits). */
  static final int SHIFT_CARD_CERT_RIGHT = 2;

  // ==================== Field Offsets in Key Reference (29 bytes) ====================

  /** Offset of AID size in key reference (0). */
  static final int KEY_REF_OFFSET_AID_SIZE = 0;

  /** Offset of AID value in key reference (1). */
  static final int KEY_REF_OFFSET_AID_VALUE = 1;

  /** Offset of serial number in key reference (17 = 1 + 16). */
  static final int KEY_REF_OFFSET_SERIAL_NUMBER = 17;

  /** Offset of key ID in key reference (25 = 1 + 16 + 8). */
  static final int KEY_REF_OFFSET_KEY_ID = 25;

  /**
   * Private constructor to prevent instantiation.
   *
   * @since 0.1.0
   */
  private CertificateConstants() {
    // Utility class
  }
}
