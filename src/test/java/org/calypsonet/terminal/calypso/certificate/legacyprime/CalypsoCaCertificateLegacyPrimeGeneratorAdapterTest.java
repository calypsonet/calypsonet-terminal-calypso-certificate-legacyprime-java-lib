/* **************************************************************************************
 * Copyright (c) 2024 Calypso Networks Association https://calypsonet.org/
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
import static org.mockito.Mockito.*;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import org.calypsonet.terminal.calypso.certificate.legacyprime.spi.CalypsoCertificateLegacyPrimeSigner;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class CalypsoCaCertificateLegacyPrimeGeneratorAdapterTest {

  @Mock private CalypsoCertificateLegacyPrimeSigner signer;

  private CalypsoCertificateLegacyPrimeStoreAdapter store;
  private CalypsoCaCertificateLegacyPrimeGeneratorAdapter generator;
  private RSAPublicKey validRsaPublicKey;
  private byte[] issuerPublicKeyReference;
  private byte[] caPublicKeyReference;

  @BeforeEach
  void setUp() throws Exception {
    MockitoAnnotations.openMocks(this);

    // Create store and add issuer key
    store = new CalypsoCertificateLegacyPrimeStoreAdapter();
    issuerPublicKeyReference = new byte[] {0x01, 0x02, 0x03};

    // Create a valid 2048-bit RSA public key with exponent 65537
    java.security.KeyPairGenerator keyGenTemp = java.security.KeyPairGenerator.getInstance("RSA");
    keyGenTemp.initialize(2048);
    java.security.KeyPair keyPairTemp = keyGenTemp.generateKeyPair();
    RSAPublicKey tempKey = (RSAPublicKey) keyPairTemp.getPublic();
    BigInteger modulus = tempKey.getModulus();
    BigInteger exponent = BigInteger.valueOf(65537);
    RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
    KeyFactory factory = KeyFactory.getInstance("RSA");
    validRsaPublicKey = (RSAPublicKey) factory.generatePublic(spec);

    // Add issuer key to store
    store.addPcaPublicKey(issuerPublicKeyReference, validRsaPublicKey);

    // Create generator
    generator =
        new CalypsoCaCertificateLegacyPrimeGeneratorAdapter(
            store, issuerPublicKeyReference, signer);

    // Create valid CA public key reference (29 bytes)
    caPublicKeyReference = new byte[29];
    for (int i = 0; i < 29; i++) {
      caPublicKeyReference[i] = (byte) i;
    }
  }

  // Tests for withCaPublicKey

  @Test
  void withCaPublicKey_whenParametersAreValid_shouldReturnSelf() {
    // When
    CalypsoCaCertificateLegacyPrimeGenerator result =
        generator.withCaPublicKey(caPublicKeyReference, validRsaPublicKey);

    // Then
    assertThat(result).isSameAs(generator);
  }

  @Test
  void withCaPublicKey_whenKeyReferenceIsNull_shouldThrowIllegalArgumentException() {
    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> generator.withCaPublicKey(null, validRsaPublicKey))
        .withMessageContaining("caPublicKeyReference");
  }

  @Test
  void withCaPublicKey_whenKeyReferenceIsNot29Bytes_shouldThrowIllegalArgumentException() {
    // Given
    byte[] invalidReference = new byte[20];

    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> generator.withCaPublicKey(invalidReference, validRsaPublicKey))
        .withMessageContaining("29");
  }

  @Test
  void withCaPublicKey_whenPublicKeyIsNull_shouldThrowIllegalArgumentException() {
    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> generator.withCaPublicKey(caPublicKeyReference, null))
        .withMessageContaining("caPublicKey");
  }

  @Test
  void withCaPublicKey_whenPublicKeyIsNot2048Bits_shouldThrowIllegalArgumentException()
      throws Exception {
    // Given
    BigInteger modulus = new BigInteger(1024, new java.util.Random());
    BigInteger exponent = BigInteger.valueOf(65537);
    RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
    KeyFactory factory = KeyFactory.getInstance("RSA");
    RSAPublicKey invalidKey = (RSAPublicKey) factory.generatePublic(spec);

    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> generator.withCaPublicKey(caPublicKeyReference, invalidKey))
        .withMessageContaining("2048");
  }

  // Tests for withStartDate

  @Test
  void withStartDate_whenParametersAreValid_shouldReturnSelf() {
    // When
    CalypsoCaCertificateLegacyPrimeGenerator result = generator.withStartDate(2024, 12, 11);

    // Then
    assertThat(result).isSameAs(generator);
  }

  @Test
  void withStartDate_whenYearIsNegative_shouldThrowIllegalArgumentException() {
    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> generator.withStartDate(-1, 12, 11))
        .withMessageContaining("year");
  }

  @Test
  void withStartDate_whenYearIsGreaterThan9999_shouldThrowIllegalArgumentException() {
    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> generator.withStartDate(10000, 12, 11))
        .withMessageContaining("year");
  }

  @Test
  void withStartDate_whenMonthIsLessThan1_shouldThrowIllegalArgumentException() {
    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> generator.withStartDate(2024, 0, 11))
        .withMessageContaining("month");
  }

  @Test
  void withStartDate_whenDayIsGreaterThan99_shouldThrowIllegalArgumentException() {
    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> generator.withStartDate(2024, 12, 100))
        .withMessageContaining("day");
  }

  // Tests for withEndDate

  @Test
  void withEndDate_whenParametersAreValid_shouldReturnSelf() {
    // When
    CalypsoCaCertificateLegacyPrimeGenerator result = generator.withEndDate(2025, 12, 11);

    // Then
    assertThat(result).isSameAs(generator);
  }

  // Tests for withTargetAid

  @Test
  void withTargetAid_whenParametersAreValid_shouldReturnSelf() {
    // Given
    byte[] aid = new byte[] {0x01, 0x02, 0x03, 0x04, 0x05};

    // When
    CalypsoCaCertificateLegacyPrimeGenerator result = generator.withTargetAid(aid, false);

    // Then
    assertThat(result).isSameAs(generator);
  }

  @Test
  void withTargetAid_whenAidIsNull_shouldThrowIllegalArgumentException() {
    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> generator.withTargetAid(null, false))
        .withMessageContaining("aid");
  }

  @Test
  void withTargetAid_whenAidIsTooShort_shouldThrowIllegalArgumentException() {
    // Given
    byte[] shortAid = new byte[] {0x01, 0x02, 0x03, 0x04};

    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> generator.withTargetAid(shortAid, false))
        .withMessageContaining("5");
  }

  @Test
  void withTargetAid_whenAidIsTooLong_shouldThrowIllegalArgumentException() {
    // Given
    byte[] longAid = new byte[17];

    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> generator.withTargetAid(longAid, false))
        .withMessageContaining("16");
  }

  @Test
  void withTargetAid_whenAidContainsOnlyZeros_shouldThrowIllegalArgumentException() {
    // Given
    byte[] zeroAid = new byte[5];

    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> generator.withTargetAid(zeroAid, false))
        .withMessageContaining("zero");
  }

  // Tests for withCaRights

  @Test
  void withCaRights_whenRightsAreValid_shouldReturnSelf() {
    // Given
    byte rights = 0x0A; // b1010 - valid

    // When
    CalypsoCaCertificateLegacyPrimeGenerator result = generator.withCaRights(rights);

    // Then
    assertThat(result).isSameAs(generator);
  }

  @Test
  void withCaRights_whenBitsB7B4AreNotZero_shouldThrowIllegalArgumentException() {
    // Given
    byte invalidRights = (byte) 0xF0; // b11110000

    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> generator.withCaRights(invalidRights))
        .withMessageContaining("b7-b4");
  }

  @Test
  void withCaRights_whenCardCertRightIs11_shouldThrowIllegalArgumentException() {
    // Given
    byte invalidRights = 0x0C; // b1100 - bits b3-b2 = 11

    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> generator.withCaRights(invalidRights))
        .withMessageContaining("reserved");
  }

  @Test
  void withCaRights_whenCaCertRightIs11_shouldThrowIllegalArgumentException() {
    // Given
    byte invalidRights = 0x03; // b0011 - bits b1-b0 = 11

    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> generator.withCaRights(invalidRights))
        .withMessageContaining("reserved");
  }

  // Tests for withCaScope

  @Test
  void withCaScope_whenScopeIs00_shouldReturnSelf() {
    // When
    CalypsoCaCertificateLegacyPrimeGenerator result = generator.withCaScope((byte) 0x00);

    // Then
    assertThat(result).isSameAs(generator);
  }

  @Test
  void withCaScope_whenScopeIs01_shouldReturnSelf() {
    // When
    CalypsoCaCertificateLegacyPrimeGenerator result = generator.withCaScope((byte) 0x01);

    // Then
    assertThat(result).isSameAs(generator);
  }

  @Test
  void withCaScope_whenScopeIsFF_shouldReturnSelf() {
    // When
    CalypsoCaCertificateLegacyPrimeGenerator result = generator.withCaScope((byte) 0xFF);

    // Then
    assertThat(result).isSameAs(generator);
  }

  @Test
  void withCaScope_whenScopeIsInvalid_shouldThrowIllegalArgumentException() {
    // Given
    byte invalidScope = 0x02;

    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> generator.withCaScope(invalidScope))
        .withMessageContaining("0x00")
        .withMessageContaining("0x01")
        .withMessageContaining("0xFF");
  }

  // Tests for generate

  @Test
  void generate_whenCaPublicKeyNotSet_shouldThrowIllegalStateException() {
    // When & Then
    assertThatIllegalStateException()
        .isThrownBy(() -> generator.generate())
        .withMessageContaining("CA public key must be set");
  }

  @Test
  void generate_whenIssuerKeyNotInStore_shouldThrowIllegalStateException() {
    // Given
    byte[] unknownIssuerRef = new byte[] {0x09, 0x09, 0x09};
    CalypsoCaCertificateLegacyPrimeGeneratorAdapter badGenerator =
        new CalypsoCaCertificateLegacyPrimeGeneratorAdapter(store, unknownIssuerRef, signer);

    badGenerator.withCaPublicKey(caPublicKeyReference, validRsaPublicKey);

    // When & Then
    assertThatIllegalStateException()
        .isThrownBy(() -> badGenerator.generate())
        .withMessageContaining("not found in store");
  }

  @Test
  void generate_whenAllRequiredParametersSet_shouldThrowUnsupportedOperationException() {
    // Given
    generator.withCaPublicKey(caPublicKeyReference, validRsaPublicKey);

    // When & Then - Method not yet implemented
    assertThatExceptionOfType(UnsupportedOperationException.class)
        .isThrownBy(() -> generator.generate())
        .withMessageContaining("Not yet implemented");
  }

  // Test builder pattern chaining

  @Test
  void builderPattern_whenChainingMethods_shouldReturnSameInstance() {
    // Given
    byte[] aid = new byte[] {0x01, 0x02, 0x03, 0x04, 0x05};

    // When
    CalypsoCaCertificateLegacyPrimeGenerator result =
        generator
            .withCaPublicKey(caPublicKeyReference, validRsaPublicKey)
            .withStartDate(2024, 1, 1)
            .withEndDate(2025, 12, 31)
            .withTargetAid(aid, false)
            .withCaRights((byte) 0x0A)
            .withCaScope((byte) 0xFF);

    // Then
    assertThat(result).isSameAs(generator);
  }
}
