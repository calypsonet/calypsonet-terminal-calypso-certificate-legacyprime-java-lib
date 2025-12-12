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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class CalypsoCertificateLegacyPrimeStoreAdapterTest {

  private CalypsoCertificateLegacyPrimeStoreAdapter store;
  private RSAPublicKey validRsaPublicKey;
  private byte[] validKeyReference;

  @BeforeEach
  void setUp() throws Exception {
    store = new CalypsoCertificateLegacyPrimeStoreAdapter();

    // Create a valid 2048-bit RSA public key with exponent 65537
    java.security.KeyPairGenerator keyGen = java.security.KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(2048);
    java.security.KeyPair keyPair = keyGen.generateKeyPair();
    validRsaPublicKey = (RSAPublicKey) keyPair.getPublic();

    validKeyReference = new byte[] {0x01, 0x02, 0x03, 0x04, 0x05};
  }

  // Tests for addPcaPublicKey(byte[], RSAPublicKey)

  @Test
  void addPcaPublicKey_whenParametersAreValid_shouldAddKeySuccessfully() {
    // When
    store.addPcaPublicKey(validKeyReference, validRsaPublicKey);

    // Then
    assertThat(store.containsPublicKeyReference(validKeyReference)).isTrue();
    assertThat(store.getPublicKey(validKeyReference)).isEqualTo(validRsaPublicKey);
  }

  @Test
  void addPcaPublicKey_whenKeyReferenceIsNull_shouldThrowIllegalArgumentException() {
    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> store.addPcaPublicKey(null, validRsaPublicKey))
        .withMessageContaining("pcaPublicKeyReference");
  }

  @Test
  void addPcaPublicKey_whenPublicKeyIsNull_shouldThrowIllegalArgumentException() {
    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> store.addPcaPublicKey(validKeyReference, (RSAPublicKey) null))
        .withMessageContaining("pcaPublicKey");
  }

  @Test
  void addPcaPublicKey_whenPublicKeyIsNot2048Bits_shouldThrowIllegalArgumentException()
      throws Exception {
    // Given
    BigInteger modulus = new BigInteger(1024, new java.util.Random());
    BigInteger exponent = BigInteger.valueOf(65537);
    RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
    KeyFactory factory = KeyFactory.getInstance("RSA");
    RSAPublicKey invalidKey = (RSAPublicKey) factory.generatePublic(spec);

    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> store.addPcaPublicKey(validKeyReference, invalidKey))
        .withMessageContaining("2048");
  }

  @Test
  void addPcaPublicKey_whenExponentIsNot65537_shouldThrowIllegalArgumentException()
      throws Exception {
    // Given - Create a key with a valid modulus but wrong exponent
    BigInteger modulus = validRsaPublicKey.getModulus();
    BigInteger exponent = BigInteger.valueOf(3);
    RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
    KeyFactory factory = KeyFactory.getInstance("RSA");
    RSAPublicKey invalidKey = (RSAPublicKey) factory.generatePublic(spec);

    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> store.addPcaPublicKey(validKeyReference, invalidKey))
        .withMessageContaining("65537");
  }

  @Test
  void addPcaPublicKey_whenKeyReferenceAlreadyExists_shouldThrowIllegalStateException() {
    // Given
    store.addPcaPublicKey(validKeyReference, validRsaPublicKey);

    // When & Then
    assertThatIllegalStateException()
        .isThrownBy(() -> store.addPcaPublicKey(validKeyReference, validRsaPublicKey))
        .withMessageContaining("already exists");
  }

  // Tests for addPcaPublicKey(byte[], byte[])

  @Test
  void addPcaPublicKeyFromModulus_whenKeyReferenceIsNull_shouldThrowIllegalArgumentException() {
    // Given
    byte[] modulus = new byte[256];

    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> store.addPcaPublicKey(null, modulus))
        .withMessageContaining("pcaPublicKeyReference");
  }

  @Test
  void addPcaPublicKeyFromModulus_whenModulusIsNull_shouldThrowIllegalArgumentException() {
    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> store.addPcaPublicKey(validKeyReference, (byte[]) null))
        .withMessageContaining("pcaPublicKeyModulus");
  }

  @Test
  void addPcaPublicKeyFromModulus_whenModulusIsNot256Bytes_shouldThrowIllegalArgumentException() {
    // Given
    byte[] invalidModulus = new byte[128];

    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> store.addPcaPublicKey(validKeyReference, invalidModulus))
        .withMessageContaining("256");
  }

  @Test
  void
      addPcaPublicKeyFromModulus_whenParametersAreValid_shouldThrowUnsupportedOperationException() {
    // Given
    byte[] modulus = new byte[256];

    // When & Then - Method not yet implemented
    assertThatExceptionOfType(UnsupportedOperationException.class)
        .isThrownBy(() -> store.addPcaPublicKey(validKeyReference, modulus))
        .withMessageContaining("Not yet implemented");
  }

  // Tests for addCalypsoCaCertificateLegacyPrime(byte[])

  @Test
  void addCalypsoCaCertificate_whenCertificateIsNull_shouldThrowIllegalArgumentException() {
    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> store.addCalypsoCaCertificateLegacyPrime(null))
        .withMessageContaining("caCertificate");
  }

  @Test
  void addCalypsoCaCertificate_whenCertificateIsNot384Bytes_shouldThrowIllegalArgumentException() {
    // Given
    byte[] invalidCertificate = new byte[256];

    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> store.addCalypsoCaCertificateLegacyPrime(invalidCertificate))
        .withMessageContaining("384");
  }

  @Test
  void addCalypsoCaCertificate_whenCertificateIsValid_shouldThrowUnsupportedOperationException() {
    // Given
    byte[] certificate = new byte[384];

    // When & Then - Method not yet implemented
    assertThatExceptionOfType(UnsupportedOperationException.class)
        .isThrownBy(() -> store.addCalypsoCaCertificateLegacyPrime(certificate))
        .withMessageContaining("Not yet implemented");
  }

  // Tests for helper methods

  @Test
  void containsPublicKeyReference_whenReferenceExists_shouldReturnTrue() {
    // Given
    store.addPcaPublicKey(validKeyReference, validRsaPublicKey);

    // When & Then
    assertThat(store.containsPublicKeyReference(validKeyReference)).isTrue();
  }

  @Test
  void containsPublicKeyReference_whenReferenceDoesNotExist_shouldReturnFalse() {
    // Given
    byte[] nonExistentReference = new byte[] {0x09, 0x08, 0x07};

    // When & Then
    assertThat(store.containsPublicKeyReference(nonExistentReference)).isFalse();
  }

  @Test
  void getPublicKey_whenReferenceExists_shouldReturnKey() {
    // Given
    store.addPcaPublicKey(validKeyReference, validRsaPublicKey);

    // When
    RSAPublicKey retrievedKey = store.getPublicKey(validKeyReference);

    // Then
    assertThat(retrievedKey).isEqualTo(validRsaPublicKey);
  }

  @Test
  void getPublicKey_whenReferenceDoesNotExist_shouldReturnNull() {
    // Given
    byte[] nonExistentReference = new byte[] {0x09, 0x08, 0x07};

    // When
    RSAPublicKey retrievedKey = store.getPublicKey(nonExistentReference);

    // Then
    assertThat(retrievedKey).isNull();
  }

  @Test
  void addPcaPublicKey_whenMultipleKeysAdded_shouldStoreAllKeysWithDifferentReferences() {
    // Given
    byte[] keyRef1 = new byte[] {0x01};
    byte[] keyRef2 = new byte[] {0x02};

    // When
    store.addPcaPublicKey(keyRef1, validRsaPublicKey);
    store.addPcaPublicKey(keyRef2, validRsaPublicKey);

    // Then
    assertThat(store.containsPublicKeyReference(keyRef1)).isTrue();
    assertThat(store.containsPublicKeyReference(keyRef2)).isTrue();
  }
}
