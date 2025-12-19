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
import java.util.Arrays;
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
    // Create a valid 29-byte key reference
    issuerPublicKeyReference = new byte[29];
    issuerPublicKeyReference[0] = 0x0B; // AID size
    System.arraycopy(
        new byte[] {0x01, 0x02, 0x03}, 0, issuerPublicKeyReference, 1, 3); // AID value (partial)

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
    caPublicKeyReference[0] = 0x0B; // AID size = 11 (valid range 5-16)
    for (int i = 1; i < 29; i++) {
      caPublicKeyReference[i] = (byte) (0x10 + i);
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
        .withMessageContaining("Key reference");
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
        .withMessageContaining("rsaPublicKey");
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

  @Test
  void withCaPublicKey_whenIssuerHasTargetAidAndTruncationAllowed_andCaAidMatches_shouldSucceed()
      throws Exception {
    // Given - Create an issuer CA certificate with target AID and truncation allowed
    Aid issuerTargetAid =
        Aid.fromUnpaddedValue(
            new byte[] {(byte) 0xA0, 0x00, 0x00, 0x02, (byte) 0x91, (byte) 0xA0, 0x01, 0x00});

    CaCertificate issuerCert = createMockIssuerCertificate(issuerTargetAid, (byte) 1);
    addCaCertificateToStore(issuerPublicKeyReference, issuerCert);

    // Recreate generator with issuer certificate in store
    generator =
        new CalypsoCaCertificateLegacyPrimeGeneratorAdapter(
            store, issuerPublicKeyReference, signer);

    // CA AID starts with issuer target AID and is longer (11 bytes)
    byte[] caAidValue =
        new byte[] {
          (byte) 0xA0, 0x00, 0x00, 0x02, (byte) 0x91, (byte) 0xA0, 0x01, 0x00, 0x02, 0x40, 0x01
        };
    Aid caAid = Aid.fromUnpaddedValue(caAidValue);
    byte[] caKeyRef =
        KeyReference.builder()
            .aid(caAid)
            .serialNumber(new byte[8])
            .keyId(new byte[4])
            .build()
            .toBytes();

    // When & Then - Should not throw
    assertThatCode(() -> generator.withCaPublicKey(caKeyRef, validRsaPublicKey))
        .doesNotThrowAnyException();
  }

  @Test
  void withCaPublicKey_whenIssuerHasTargetAidAndTruncationForbidden_andCaAidMatches_shouldSucceed()
      throws Exception {
    // Given - Create an issuer CA certificate with target AID and truncation forbidden
    Aid issuerTargetAid =
        Aid.fromUnpaddedValue(
            new byte[] {(byte) 0xA0, 0x00, 0x00, 0x02, (byte) 0x91, (byte) 0xA0, 0x01, 0x00});

    CaCertificate issuerCert = createMockIssuerCertificate(issuerTargetAid, (byte) 0);
    addCaCertificateToStore(issuerPublicKeyReference, issuerCert);

    // Recreate generator with issuer certificate in store
    generator =
        new CalypsoCaCertificateLegacyPrimeGeneratorAdapter(
            store, issuerPublicKeyReference, signer);

    // CA AID exactly matches issuer target AID
    byte[] caKeyRef =
        KeyReference.builder()
            .aid(issuerTargetAid)
            .serialNumber(new byte[8])
            .keyId(new byte[4])
            .build()
            .toBytes();

    // When & Then - Should not throw
    assertThatCode(() -> generator.withCaPublicKey(caKeyRef, validRsaPublicKey))
        .doesNotThrowAnyException();
  }

  @Test
  void withCaPublicKey_whenTruncationAllowed_andCaAidTooShort_shouldThrowIllegalArgumentException()
      throws Exception {
    // Given
    Aid issuerTargetAid =
        Aid.fromUnpaddedValue(
            new byte[] {(byte) 0xA0, 0x00, 0x00, 0x02, (byte) 0x91, (byte) 0xA0, 0x01, 0x00});

    CaCertificate issuerCert = createMockIssuerCertificate(issuerTargetAid, (byte) 1);
    addCaCertificateToStore(issuerPublicKeyReference, issuerCert);

    generator =
        new CalypsoCaCertificateLegacyPrimeGeneratorAdapter(
            store, issuerPublicKeyReference, signer);

    // CA AID is too short (6 bytes < 8 bytes)
    Aid caAid = Aid.fromUnpaddedValue(Arrays.copyOf(issuerTargetAid.getUnpaddedValue(), 6));
    byte[] caKeyRef =
        KeyReference.builder()
            .aid(caAid)
            .serialNumber(new byte[8])
            .keyId(new byte[4])
            .build()
            .toBytes();

    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> generator.withCaPublicKey(caKeyRef, validRsaPublicKey))
        .withMessageContaining("does not match issuer's target AID constraints");
  }

  @Test
  void
      withCaPublicKey_whenTruncationAllowed_andCaAidDoesNotStartWithIssuerAid_shouldThrowIllegalArgumentException()
          throws Exception {
    // Given
    Aid issuerTargetAid =
        Aid.fromUnpaddedValue(
            new byte[] {(byte) 0xA0, 0x00, 0x00, 0x02, (byte) 0x91, (byte) 0xA0, 0x01, 0x00});

    CaCertificate issuerCert = createMockIssuerCertificate(issuerTargetAid, (byte) 1);
    addCaCertificateToStore(issuerPublicKeyReference, issuerCert);

    generator =
        new CalypsoCaCertificateLegacyPrimeGeneratorAdapter(
            store, issuerPublicKeyReference, signer);

    // CA AID doesn't start with issuer's target AID
    Aid caAid = Aid.fromUnpaddedValue(new byte[] {(byte) 0xB0, 0x00, 0x00, 0x02, (byte) 0x91});
    byte[] caKeyRef =
        KeyReference.builder()
            .aid(caAid)
            .serialNumber(new byte[8])
            .keyId(new byte[4])
            .build()
            .toBytes();

    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> generator.withCaPublicKey(caKeyRef, validRsaPublicKey))
        .withMessageContaining("does not match issuer's target AID constraints");
  }

  @Test
  void
      withCaPublicKey_whenTruncationForbidden_andCaAidSizeDifferent_shouldThrowIllegalArgumentException()
          throws Exception {
    // Given
    Aid issuerTargetAid =
        Aid.fromUnpaddedValue(
            new byte[] {(byte) 0xA0, 0x00, 0x00, 0x02, (byte) 0x91, (byte) 0xA0, 0x01, 0x00});

    CaCertificate issuerCert = createMockIssuerCertificate(issuerTargetAid, (byte) 0);
    addCaCertificateToStore(issuerPublicKeyReference, issuerCert);

    generator =
        new CalypsoCaCertificateLegacyPrimeGeneratorAdapter(
            store, issuerPublicKeyReference, signer);

    // CA AID has different size
    Aid caAid = Aid.fromUnpaddedValue(Arrays.copyOf(issuerTargetAid.getUnpaddedValue(), 10));
    byte[] caKeyRef =
        KeyReference.builder()
            .aid(caAid)
            .serialNumber(new byte[8])
            .keyId(new byte[4])
            .build()
            .toBytes();

    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> generator.withCaPublicKey(caKeyRef, validRsaPublicKey))
        .withMessageContaining("does not match issuer's target AID constraints");
  }

  @Test
  void
      withCaPublicKey_whenTruncationForbidden_andCaAidContentDifferent_shouldThrowIllegalArgumentException()
          throws Exception {
    // Given
    Aid issuerTargetAid =
        Aid.fromUnpaddedValue(
            new byte[] {(byte) 0xA0, 0x00, 0x00, 0x02, (byte) 0x91, (byte) 0xA0, 0x01, 0x00});

    CaCertificate issuerCert = createMockIssuerCertificate(issuerTargetAid, (byte) 0);
    addCaCertificateToStore(issuerPublicKeyReference, issuerCert);

    generator =
        new CalypsoCaCertificateLegacyPrimeGeneratorAdapter(
            store, issuerPublicKeyReference, signer);

    // CA AID has same size but different content
    byte[] wrongAidValue = issuerTargetAid.getUnpaddedValue();
    wrongAidValue[3] = 0x03; // Change one byte (was 0x00)
    Aid caAid = Aid.fromUnpaddedValue(wrongAidValue);
    byte[] caKeyRef =
        KeyReference.builder()
            .aid(caAid)
            .serialNumber(new byte[8])
            .keyId(new byte[4])
            .build()
            .toBytes();

    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> generator.withCaPublicKey(caKeyRef, validRsaPublicKey))
        .withMessageContaining("does not match issuer's target AID constraints");
  }

  @Test
  void withCaPublicKey_whenIssuerHasNoTargetAid_shouldNotValidateAid() throws Exception {
    // Given - Issuer has no specific target AID (null)
    CaCertificate issuerCert = createMockIssuerCertificate(null, (byte) 0);
    addCaCertificateToStore(issuerPublicKeyReference, issuerCert);

    generator =
        new CalypsoCaCertificateLegacyPrimeGeneratorAdapter(
            store, issuerPublicKeyReference, signer);

    // CA with any AID
    Aid caAid =
        Aid.fromUnpaddedValue(
            new byte[] {(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF});
    byte[] caKeyRef =
        KeyReference.builder()
            .aid(caAid)
            .serialNumber(new byte[8])
            .keyId(new byte[4])
            .build()
            .toBytes();

    // When & Then - Should not throw (no validation)
    assertThatCode(() -> generator.withCaPublicKey(caKeyRef, validRsaPublicKey))
        .doesNotThrowAnyException();
  }

  /**
   * Helper method to create a mock issuer certificate with specified AID parameters.
   *
   * @param targetAid The target AID.
   * @param operatingMode The operating mode (bit 0 = truncation flag).
   * @return A CaCertificate instance.
   */
  private CaCertificate createMockIssuerCertificate(Aid targetAid, byte operatingMode) {
    // Create a valid issuer key reference for the mock certificate
    byte[] mockIssuerKeyRef = new byte[29];
    mockIssuerKeyRef[0] = 0x08; // AID size = 8 (valid range 5-16)
    for (int i = 1; i < 17; i++) {
      mockIssuerKeyRef[i] = (byte) (0x20 + i);
    }

    // If targetAid is null, use RFU Aid (size=0xFF, all zeros)
    Aid effectiveTargetAid = targetAid;
    if (effectiveTargetAid == null) {
      effectiveTargetAid = Aid.fromBytes((byte) 0xFF, new byte[16]);
    }

    // Use default date 2000-01-01 (0x20000101 in BCD)
    byte[] defaultDate = new byte[] {0x20, 0x00, 0x01, 0x01};

    return CaCertificate.builder()
        .certType((byte) 0x90)
        .structureVersion((byte) 0x01)
        .issuerKeyReference(mockIssuerKeyRef)
        .caTargetKeyReference(issuerPublicKeyReference)
        .startDate(defaultDate)
        .caRfu1(new byte[4])
        .caRights((byte) 0x01)
        .caScope((byte) 0xFF)
        .endDate(defaultDate)
        .caTargetAid(effectiveTargetAid.getSize(), effectiveTargetAid.getPaddedValue())
        .caOperatingMode(operatingMode)
        .caRfu2(new byte[2])
        .publicKeyHeader(new byte[34])
        .signature(new byte[256])
        .rsaPublicKey(validRsaPublicKey)
        .build();
  }

  /**
   * Helper method to add a CA certificate directly to the store for testing purposes.
   *
   * <p>This method uses reflection to access the private caCertificates map in the store and add
   * the certificate directly, bypassing signature verification which would fail with mock data.
   *
   * @param keyReference The key reference for the certificate.
   * @param certificate The CaCertificate to add.
   */
  private void addCaCertificateToStore(byte[] keyReference, CaCertificate certificate) {
    try {
      java.lang.reflect.Field field =
          CalypsoCertificateLegacyPrimeStoreAdapter.class.getDeclaredField("caCertificates");
      field.setAccessible(true);
      @SuppressWarnings("unchecked")
      java.util.Map<String, CaCertificate> caCertificates =
          (java.util.Map<String, CaCertificate>) field.get(store);
      caCertificates.put(org.eclipse.keyple.core.util.HexUtil.toHex(keyReference), certificate);
    } catch (Exception e) {
      throw new RuntimeException("Failed to add certificate to store for testing", e);
    }
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
        .withMessageContaining("AID value cannot be null");
  }

  @Test
  void withTargetAid_whenAidIsTooShort_shouldThrowIllegalArgumentException() {
    // Given
    byte[] shortAid = new byte[] {0x01, 0x02, 0x03, 0x04};

    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> generator.withTargetAid(shortAid, false))
        .withMessageContaining("5 and 16");
  }

  @Test
  void withTargetAid_whenAidIsTooLong_shouldThrowIllegalArgumentException() {
    // Given
    byte[] longAid = new byte[17];

    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> generator.withTargetAid(longAid, false))
        .withMessageContaining("5 and 16");
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
        .withMessageContaining("Unknown CA scope");
  }

  // Tests for generate

  @Test
  void generate_whenCaPublicKeyNotSet_shouldThrowIllegalArgumentException() {
    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> generator.generate())
        .withMessageContaining("caTargetKeyReference");
  }

  @Test
  void generate_whenIssuerKeyNotInStore_shouldThrowIllegalStateException() {
    // Given - Create an issuer reference that doesn't exist in the store
    byte[] unknownIssuerRef = new byte[] {0x09, 0x09, 0x09};
    CalypsoCertificateLegacyPrimeApiFactoryAdapter factory =
        new CalypsoCertificateLegacyPrimeApiFactoryAdapter();

    // When & Then - Factory should throw when issuer key is not in store
    assertThatIllegalStateException()
        .isThrownBy(
            () -> factory.createCalypsoCaCertificateLegacyPrimeGenerator(unknownIssuerRef, signer))
        .withMessageContaining("not found in store");
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
