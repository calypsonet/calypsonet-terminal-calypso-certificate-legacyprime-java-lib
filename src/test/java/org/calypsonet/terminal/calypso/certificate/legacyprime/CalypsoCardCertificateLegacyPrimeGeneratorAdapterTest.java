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
import org.calypsonet.terminal.calypso.certificate.legacyprime.spi.CalypsoCertificateLegacyPrimeSigner;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class CalypsoCardCertificateLegacyPrimeGeneratorAdapterTest {

  @Mock private CalypsoCertificateLegacyPrimeSigner signer;

  private CalypsoCertificateLegacyPrimeStoreAdapter store;
  private CalypsoCardCertificateLegacyPrimeGeneratorAdapter generator;
  private byte[] issuerPublicKeyReference;
  private byte[] cardPublicKey;
  private byte[] cardAid;
  private byte[] cardSerialNumber;
  private byte[] cardStartupInfo;

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
    RSAPublicKey validRsaPublicKey = (RSAPublicKey) factory.generatePublic(spec);

    // Add issuer key to store
    store.addPcaPublicKey(issuerPublicKeyReference, validRsaPublicKey);

    // Create generator
    generator =
        new CalypsoCardCertificateLegacyPrimeGeneratorAdapter(
            store, issuerPublicKeyReference, signer);

    // Create valid test data
    cardPublicKey = new byte[64];
    for (int i = 0; i < 64; i++) {
      cardPublicKey[i] = (byte) i;
    }

    cardAid = new byte[] {0x01, 0x02, 0x03, 0x04, 0x05};
    cardSerialNumber = new byte[8];
    for (int i = 0; i < 8; i++) {
      cardSerialNumber[i] = (byte) i;
    }

    cardStartupInfo = new byte[7];
    for (int i = 0; i < 7; i++) {
      cardStartupInfo[i] = (byte) i;
    }
  }

  // Tests for withCardPublicKey

  @Test
  void withCardPublicKey_whenParametersAreValid_shouldReturnSelf() {
    // When
    CalypsoCardCertificateLegacyPrimeGenerator result = generator.withCardPublicKey(cardPublicKey);

    // Then
    assertThat(result).isSameAs(generator);
  }

  @Test
  void withCardPublicKey_whenKeyIsNull_shouldThrowIllegalArgumentException() {
    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> generator.withCardPublicKey(null))
        .withMessageContaining("cardPublicKey");
  }

  @Test
  void withCardPublicKey_whenKeyIsNot64Bytes_shouldThrowIllegalArgumentException() {
    // Given
    byte[] invalidKey = new byte[32];

    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> generator.withCardPublicKey(invalidKey))
        .withMessageContaining("64");
  }

  // Tests for withStartDate

  @Test
  void withStartDate_whenParametersAreValid_shouldReturnSelf() {
    // When
    CalypsoCardCertificateLegacyPrimeGenerator result = generator.withStartDate(2024, 12, 11);

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
    CalypsoCardCertificateLegacyPrimeGenerator result = generator.withEndDate(2025, 12, 11);

    // Then
    assertThat(result).isSameAs(generator);
  }

  // Tests for withCardAid

  @Test
  void withCardAid_whenParametersAreValid_shouldReturnSelf() {
    // When
    CalypsoCardCertificateLegacyPrimeGenerator result = generator.withCardAid(cardAid);

    // Then
    assertThat(result).isSameAs(generator);
  }

  @Test
  void withCardAid_whenAidIsNull_shouldThrowIllegalArgumentException() {
    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> generator.withCardAid(null))
        .withMessageContaining("aid");
  }

  @Test
  void withCardAid_whenAidIsTooShort_shouldThrowIllegalArgumentException() {
    // Given
    byte[] shortAid = new byte[] {0x01, 0x02, 0x03, 0x04};

    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> generator.withCardAid(shortAid))
        .withMessageContaining("5");
  }

  @Test
  void withCardAid_whenAidIsTooLong_shouldThrowIllegalArgumentException() {
    // Given
    byte[] longAid = new byte[17];

    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> generator.withCardAid(longAid))
        .withMessageContaining("16");
  }

  @Test
  void withCardAid_whenAidContainsOnlyZeros_shouldThrowIllegalArgumentException() {
    // Given
    byte[] zeroAid = new byte[5];

    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> generator.withCardAid(zeroAid))
        .withMessageContaining("zero");
  }

  // Tests for withCardSerialNumber

  @Test
  void withCardSerialNumber_whenParametersAreValid_shouldReturnSelf() {
    // When
    CalypsoCardCertificateLegacyPrimeGenerator result =
        generator.withCardSerialNumber(cardSerialNumber);

    // Then
    assertThat(result).isSameAs(generator);
  }

  @Test
  void withCardSerialNumber_whenSerialNumberIsNull_shouldThrowIllegalArgumentException() {
    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> generator.withCardSerialNumber(null))
        .withMessageContaining("serialNumber");
  }

  @Test
  void withCardSerialNumber_whenSerialNumberIsNot8Bytes_shouldThrowIllegalArgumentException() {
    // Given
    byte[] invalidSerialNumber = new byte[10];

    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> generator.withCardSerialNumber(invalidSerialNumber))
        .withMessageContaining("8");
  }

  // Tests for withCardStartupInfo

  @Test
  void withCardStartupInfo_whenParametersAreValid_shouldReturnSelf() {
    // When
    CalypsoCardCertificateLegacyPrimeGenerator result =
        generator.withCardStartupInfo(cardStartupInfo);

    // Then
    assertThat(result).isSameAs(generator);
  }

  @Test
  void withCardStartupInfo_whenStartupInfoIsNull_shouldThrowIllegalArgumentException() {
    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> generator.withCardStartupInfo(null))
        .withMessageContaining("startupInfo");
  }

  @Test
  void withCardStartupInfo_whenStartupInfoIsNot7Bytes_shouldThrowIllegalArgumentException() {
    // Given
    byte[] invalidStartupInfo = new byte[5];

    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> generator.withCardStartupInfo(invalidStartupInfo))
        .withMessageContaining("7");
  }

  // Tests for withIndex

  @Test
  void withIndex_whenParametersAreValid_shouldReturnSelf() {
    // When
    CalypsoCardCertificateLegacyPrimeGenerator result = generator.withIndex(42);

    // Then
    assertThat(result).isSameAs(generator);
  }

  @Test
  void withIndex_whenIndexIsZero_shouldReturnSelf() {
    // When
    CalypsoCardCertificateLegacyPrimeGenerator result = generator.withIndex(0);

    // Then
    assertThat(result).isSameAs(generator);
  }

  @Test
  void withIndex_whenIndexIsNegative_shouldReturnSelf() {
    // When - No validation on index value
    CalypsoCardCertificateLegacyPrimeGenerator result = generator.withIndex(-1);

    // Then
    assertThat(result).isSameAs(generator);
  }

  // Tests for generate

  @Test
  void generate_whenCardPublicKeyNotSet_shouldThrowIllegalStateException() {
    // Given
    generator.withCardAid(cardAid);
    generator.withCardSerialNumber(cardSerialNumber);
    generator.withCardStartupInfo(cardStartupInfo);

    // When & Then
    assertThatIllegalStateException()
        .isThrownBy(() -> generator.generate())
        .withMessageContaining("Card public key must be set");
  }

  @Test
  void generate_whenCardAidNotSet_shouldThrowIllegalStateException() {
    // Given
    generator.withCardPublicKey(cardPublicKey);
    generator.withCardSerialNumber(cardSerialNumber);
    generator.withCardStartupInfo(cardStartupInfo);

    // When & Then
    assertThatIllegalStateException()
        .isThrownBy(() -> generator.generate())
        .withMessageContaining("Card AID must be set");
  }

  @Test
  void generate_whenCardSerialNumberNotSet_shouldThrowIllegalStateException() {
    // Given
    generator.withCardPublicKey(cardPublicKey);
    generator.withCardAid(cardAid);
    generator.withCardStartupInfo(cardStartupInfo);

    // When & Then
    assertThatIllegalStateException()
        .isThrownBy(() -> generator.generate())
        .withMessageContaining("Card serial number must be set");
  }

  @Test
  void generate_whenCardStartupInfoNotSet_shouldThrowIllegalStateException() {
    // Given
    generator.withCardPublicKey(cardPublicKey);
    generator.withCardAid(cardAid);
    generator.withCardSerialNumber(cardSerialNumber);

    // When & Then
    assertThatIllegalStateException()
        .isThrownBy(() -> generator.generate())
        .withMessageContaining("Card startup info must be set");
  }

  @Test
  void generate_whenIssuerKeyNotInStore_shouldThrowIllegalStateException() {
    // Given
    byte[] unknownIssuerRef = new byte[] {0x09, 0x09, 0x09};
    CalypsoCardCertificateLegacyPrimeGeneratorAdapter badGenerator =
        new CalypsoCardCertificateLegacyPrimeGeneratorAdapter(store, unknownIssuerRef, signer);

    badGenerator.withCardPublicKey(cardPublicKey);
    badGenerator.withCardAid(cardAid);
    badGenerator.withCardSerialNumber(cardSerialNumber);
    badGenerator.withCardStartupInfo(cardStartupInfo);

    // When & Then
    assertThatIllegalStateException()
        .isThrownBy(() -> badGenerator.generate())
        .withMessageContaining("not found in store");
  }

  // Test builder pattern chaining

  @Test
  void builderPattern_whenChainingMethods_shouldReturnSameInstance() {
    // When
    CalypsoCardCertificateLegacyPrimeGenerator result =
        generator
            .withCardPublicKey(cardPublicKey)
            .withStartDate(2024, 1, 1)
            .withEndDate(2025, 12, 31)
            .withCardAid(cardAid)
            .withCardSerialNumber(cardSerialNumber)
            .withCardStartupInfo(cardStartupInfo)
            .withIndex(5);

    // Then
    assertThat(result).isSameAs(generator);
  }
}
