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

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import org.calypsonet.terminal.calypso.certificate.legacyprime.spi.CalypsoCertificateLegacyPrimeSigner;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class CalypsoCertificateLegacyPrimeApiFactoryAdapterTest {

  @Mock private CalypsoCertificateLegacyPrimeSigner signer;

  private CalypsoCertificateLegacyPrimeApiFactoryAdapter factory;
  private byte[] issuerPublicKeyReference;
  private RSAPublicKey validRsaPublicKey;

  @BeforeEach
  void setUp() throws Exception {
    MockitoAnnotations.openMocks(this);

    factory = new CalypsoCertificateLegacyPrimeApiFactoryAdapter();

    // Create a valid 2048-bit RSA public key with exponent 65537
    java.security.KeyPairGenerator keyGenTemp = java.security.KeyPairGenerator.getInstance("RSA");
    keyGenTemp.initialize(2048);
    java.security.KeyPair keyPairTemp = keyGenTemp.generateKeyPair();
    RSAPublicKey tempKey = (RSAPublicKey) keyPairTemp.getPublic();
    BigInteger modulus = tempKey.getModulus();
    BigInteger exponent = BigInteger.valueOf(65537);
    RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    validRsaPublicKey = (RSAPublicKey) keyFactory.generatePublic(spec);

    issuerPublicKeyReference = new byte[] {0x01, 0x02, 0x03};

    // Add issuer key to store
    factory
        .getCalypsoCertificateLegacyPrimeStore()
        .addPcaPublicKey(issuerPublicKeyReference, validRsaPublicKey);
  }

  // Tests for getCalypsoCertificateLegacyPrimeStore

  @Test
  void getCalypsoCertificateLegacyPrimeStore_shouldReturnNonNullStore() {
    // When
    CalypsoCertificateLegacyPrimeStore store = factory.getCalypsoCertificateLegacyPrimeStore();

    // Then
    assertThat(store).isNotNull();
  }

  @Test
  void getCalypsoCertificateLegacyPrimeStore_shouldReturnSameInstanceOnMultipleCalls() {
    // When
    CalypsoCertificateLegacyPrimeStore store1 = factory.getCalypsoCertificateLegacyPrimeStore();
    CalypsoCertificateLegacyPrimeStore store2 = factory.getCalypsoCertificateLegacyPrimeStore();

    // Then
    assertThat(store1).isSameAs(store2);
  }

  // Tests for createCalypsoCaCertificateLegacyPrimeGenerator

  @Test
  void createCalypsoCaCertificateGenerator_whenParametersAreValid_shouldReturnNonNullGenerator() {
    // When
    CalypsoCaCertificateLegacyPrimeGenerator generator =
        factory.createCalypsoCaCertificateLegacyPrimeGenerator(issuerPublicKeyReference, signer);

    // Then
    assertThat(generator).isNotNull();
  }

  @Test
  void
      createCalypsoCaCertificateGenerator_whenIssuerReferenceIsNull_shouldThrowIllegalArgumentException() {
    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> factory.createCalypsoCaCertificateLegacyPrimeGenerator(null, signer))
        .withMessageContaining("issuerPublicKeyReference");
  }

  @Test
  void createCalypsoCaCertificateGenerator_whenSignerIsNull_shouldThrowIllegalArgumentException() {
    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(
            () ->
                factory.createCalypsoCaCertificateLegacyPrimeGenerator(
                    issuerPublicKeyReference, null))
        .withMessageContaining("caCertificateSigner");
  }

  @Test
  void
      createCalypsoCaCertificateGenerator_whenIssuerReferenceNotInStore_shouldThrowIllegalStateException() {
    // Given
    byte[] unknownReference = new byte[] {0x09, 0x09, 0x09};

    // When & Then
    assertThatIllegalStateException()
        .isThrownBy(
            () -> factory.createCalypsoCaCertificateLegacyPrimeGenerator(unknownReference, signer))
        .withMessageContaining("not found in store");
  }

  @Test
  void
      createCalypsoCaCertificateGenerator_whenCalledMultipleTimes_shouldReturnDifferentInstances() {
    // When
    CalypsoCaCertificateLegacyPrimeGenerator generator1 =
        factory.createCalypsoCaCertificateLegacyPrimeGenerator(issuerPublicKeyReference, signer);
    CalypsoCaCertificateLegacyPrimeGenerator generator2 =
        factory.createCalypsoCaCertificateLegacyPrimeGenerator(issuerPublicKeyReference, signer);

    // Then
    assertThat(generator1).isNotSameAs(generator2);
  }

  // Tests for createCalypsoCardCertificateLegacyPrimeGenerator

  @Test
  void createCalypsoCardCertificateGenerator_whenParametersAreValid_shouldReturnNonNullGenerator() {
    // When
    CalypsoCardCertificateLegacyPrimeGenerator generator =
        factory.createCalypsoCardCertificateLegacyPrimeGenerator(issuerPublicKeyReference, signer);

    // Then
    assertThat(generator).isNotNull();
  }

  @Test
  void
      createCalypsoCardCertificateGenerator_whenIssuerReferenceIsNull_shouldThrowIllegalArgumentException() {
    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> factory.createCalypsoCardCertificateLegacyPrimeGenerator(null, signer))
        .withMessageContaining("issuerPublicKeyReference");
  }

  @Test
  void
      createCalypsoCardCertificateGenerator_whenSignerIsNull_shouldThrowIllegalArgumentException() {
    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(
            () ->
                factory.createCalypsoCardCertificateLegacyPrimeGenerator(
                    issuerPublicKeyReference, null))
        .withMessageContaining("cardCertificateSigner");
  }

  @Test
  void
      createCalypsoCardCertificateGenerator_whenIssuerReferenceNotInStore_shouldThrowIllegalStateException() {
    // Given
    byte[] unknownReference = new byte[] {0x09, 0x09, 0x09};

    // When & Then
    assertThatIllegalStateException()
        .isThrownBy(
            () ->
                factory.createCalypsoCardCertificateLegacyPrimeGenerator(unknownReference, signer))
        .withMessageContaining("not found in store");
  }

  @Test
  void
      createCalypsoCardCertificateGenerator_whenCalledMultipleTimes_shouldReturnDifferentInstances() {
    // When
    CalypsoCardCertificateLegacyPrimeGenerator generator1 =
        factory.createCalypsoCardCertificateLegacyPrimeGenerator(issuerPublicKeyReference, signer);
    CalypsoCardCertificateLegacyPrimeGenerator generator2 =
        factory.createCalypsoCardCertificateLegacyPrimeGenerator(issuerPublicKeyReference, signer);

    // Then
    assertThat(generator1).isNotSameAs(generator2);
  }

  // Integration tests

  @Test
  void integrationTest_shouldCreateGeneratorsUsingSharedStore() {
    // Given
    byte[] anotherKeyRef = new byte[] {0x04, 0x05, 0x06};
    factory
        .getCalypsoCertificateLegacyPrimeStore()
        .addPcaPublicKey(anotherKeyRef, validRsaPublicKey);

    // When
    CalypsoCaCertificateLegacyPrimeGenerator caGenerator1 =
        factory.createCalypsoCaCertificateLegacyPrimeGenerator(issuerPublicKeyReference, signer);
    CalypsoCaCertificateLegacyPrimeGenerator caGenerator2 =
        factory.createCalypsoCaCertificateLegacyPrimeGenerator(anotherKeyRef, signer);
    CalypsoCardCertificateLegacyPrimeGenerator cardGenerator =
        factory.createCalypsoCardCertificateLegacyPrimeGenerator(issuerPublicKeyReference, signer);

    // Then - All generators should be created successfully using the shared store
    assertThat(caGenerator1).isNotNull();
    assertThat(caGenerator2).isNotNull();
    assertThat(cardGenerator).isNotNull();
  }
}
