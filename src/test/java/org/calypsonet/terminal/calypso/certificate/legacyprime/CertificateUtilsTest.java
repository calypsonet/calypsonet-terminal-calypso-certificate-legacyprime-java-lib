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

import static org.assertj.core.api.Assertions.*;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import org.junit.jupiter.api.Test;

class CertificateUtilsTest {

  // Tests for checkRSA2048PublicKey()

  @Test
  void checkRSA2048PublicKey_whenKeyIsValid_shouldNotThrowException() throws Exception {
    // Given - Create a valid 2048-bit RSA public key with exponent 65537
    java.security.KeyPairGenerator keyGen = java.security.KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(2048);
    java.security.KeyPair keyPair = keyGen.generateKeyPair();
    RSAPublicKey validKey = (RSAPublicKey) keyPair.getPublic();

    // When & Then
    assertThatCode(() -> CertificateUtils.checkRSA2048PublicKey(validKey))
        .doesNotThrowAnyException();
  }

  @Test
  void checkRSA2048PublicKey_whenKeyIsNull_shouldThrowIllegalArgumentException() {
    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> CertificateUtils.checkRSA2048PublicKey(null))
        .withMessageContaining("rsaPublicKey");
  }

  @Test
  void checkRSA2048PublicKey_whenKeyIsNot2048Bits_shouldThrowIllegalArgumentException()
      throws Exception {
    // Given - Create a 1024-bit RSA key
    BigInteger modulus = new BigInteger(1024, new java.util.Random());
    BigInteger exponent = BigInteger.valueOf(65537);
    RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
    KeyFactory factory = KeyFactory.getInstance("RSA");
    RSAPublicKey invalidKey = (RSAPublicKey) factory.generatePublic(spec);

    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> CertificateUtils.checkRSA2048PublicKey(invalidKey))
        .withMessageContaining("2048");
  }

  @Test
  void checkRSA2048PublicKey_whenExponentIsNot65537_shouldThrowIllegalArgumentException()
      throws Exception {
    // Given - Create a key with valid modulus but wrong exponent
    java.security.KeyPairGenerator keyGen = java.security.KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(2048);
    java.security.KeyPair keyPair = keyGen.generateKeyPair();
    RSAPublicKey tempKey = (RSAPublicKey) keyPair.getPublic();
    BigInteger modulus = tempKey.getModulus();
    BigInteger exponent = BigInteger.valueOf(3); // Wrong exponent
    RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
    KeyFactory factory = KeyFactory.getInstance("RSA");
    RSAPublicKey invalidKey = (RSAPublicKey) factory.generatePublic(spec);

    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> CertificateUtils.checkRSA2048PublicKey(invalidKey))
        .withMessageContaining("65537");
  }

  // Tests for generateRSAPublicKeyFromModulus()

  @Test
  void generateRSAPublicKeyFromModulus_whenModulusIsValid_shouldReturnValidKey() {
    // Given - Create a 256-byte modulus
    byte[] modulus = new byte[256];
    for (int i = 0; i < modulus.length; i++) {
      modulus[i] = (byte) (i % 256);
    }
    // Set first byte to non-zero to ensure positive BigInteger
    modulus[0] = 0x01;

    // When
    RSAPublicKey publicKey = CertificateUtils.generateRSAPublicKeyFromModulus(modulus);

    // Then
    assertThat(publicKey).isNotNull();
    assertThat(publicKey.getModulus().bitLength()).isGreaterThan(0);
    assertThat(publicKey.getPublicExponent().intValue()).isEqualTo(65537);
  }

  @Test
  void generateRSAPublicKeyFromModulus_whenModulusIsNull_shouldThrowIllegalArgumentException() {
    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> CertificateUtils.generateRSAPublicKeyFromModulus(null))
        .withMessageContaining("Failed to create RSA public key");
  }

  @Test
  void generateRSAPublicKeyFromModulus_whenModulusIsInvalid_shouldThrowIllegalArgumentException() {
    // Given - Empty modulus
    byte[] invalidModulus = new byte[0];

    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> CertificateUtils.generateRSAPublicKeyFromModulus(invalidModulus))
        .withMessageContaining("Failed to create RSA public key");
  }

  // Tests for encodeDateBcd()

  @Test
  void encodeDateBcd_whenDateIsValid_shouldReturnCorrectBcdEncoding() {
    // Given
    int year = 2024;
    int month = 12;
    int day = 31;

    // When
    byte[] encoded = CertificateUtils.encodeDateBcd(year, month, day);

    // Then
    assertThat(encoded).hasSize(4);
    // 2024 => 0x20 0x24
    assertThat(encoded[0]).isEqualTo((byte) 0x20);
    assertThat(encoded[1]).isEqualTo((byte) 0x24);
    // 12 => 0x12
    assertThat(encoded[2]).isEqualTo((byte) 0x12);
    // 31 => 0x31
    assertThat(encoded[3]).isEqualTo((byte) 0x31);
  }

  @Test
  void encodeDateBcd_whenYearIs0_shouldEncodeCorrectly() {
    // Given
    int year = 0;
    int month = 1;
    int day = 1;

    // When
    byte[] encoded = CertificateUtils.encodeDateBcd(year, month, day);

    // Then
    assertThat(encoded).hasSize(4);
    assertThat(encoded[0]).isEqualTo((byte) 0x00);
    assertThat(encoded[1]).isEqualTo((byte) 0x00);
    assertThat(encoded[2]).isEqualTo((byte) 0x01);
    assertThat(encoded[3]).isEqualTo((byte) 0x01);
  }

  @Test
  void encodeDateBcd_whenYearIs9999_shouldEncodeCorrectly() {
    // Given
    int year = 9999;
    int month = 99;
    int day = 99;

    // When
    byte[] encoded = CertificateUtils.encodeDateBcd(year, month, day);

    // Then
    assertThat(encoded).hasSize(4);
    // 9999 => 0x99 0x99
    assertThat(encoded[0]).isEqualTo((byte) 0x99);
    assertThat(encoded[1]).isEqualTo((byte) 0x99);
    // 99 => 0x99
    assertThat(encoded[2]).isEqualTo((byte) 0x99);
    // 99 => 0x99
    assertThat(encoded[3]).isEqualTo((byte) 0x99);
  }

  @Test
  void encodeDateBcd_whenDateHasSingleDigits_shouldEncodeWithLeadingZeros() {
    // Given
    int year = 5;
    int month = 3;
    int day = 7;

    // When
    byte[] encoded = CertificateUtils.encodeDateBcd(year, month, day);

    // Then
    assertThat(encoded).hasSize(4);
    // 0005 => 0x00 0x05
    assertThat(encoded[0]).isEqualTo((byte) 0x00);
    assertThat(encoded[1]).isEqualTo((byte) 0x05);
    // 03 => 0x03
    assertThat(encoded[2]).isEqualTo((byte) 0x03);
    // 07 => 0x07
    assertThat(encoded[3]).isEqualTo((byte) 0x07);
  }
}
