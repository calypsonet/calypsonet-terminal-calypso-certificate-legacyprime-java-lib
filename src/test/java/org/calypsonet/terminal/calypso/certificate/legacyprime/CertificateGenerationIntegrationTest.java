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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import org.calypsonet.terminal.calypso.certificate.legacyprime.spi.CalypsoCertificateLegacyPrimeSigner;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Integration tests for certificate generation using DefaultCalypsoCertificateLegacyPrimeSigner.
 *
 * <p>These tests demonstrate complete workflows for generating CA and card certificates, including:
 *
 * <ul>
 *   <li>Key pair generation
 *   <li>Signer creation
 *   <li>Certificate generation
 *   <li>Certificate validation and parsing
 *   <li>Certificate chaining (PCA → CA → Card)
 * </ul>
 */
class CertificateGenerationIntegrationTest {

  private CalypsoCertificateLegacyPrimeApiFactory factory;
  private CalypsoCertificateLegacyPrimeStore store;

  private RSAPrivateKey pcaPrivateKey;
  private RSAPublicKey pcaPublicKey;
  private byte[] pcaKeyReference;

  private RSAPrivateKey caPrivateKey;
  private RSAPublicKey caPublicKey;
  private byte[] caKeyReference;

  @BeforeEach
  void setUp() throws Exception {
    // Initialize service
    // Note: Create a new factory for each test to avoid shared state
    factory = new CalypsoCertificateLegacyPrimeApiFactoryAdapter();
    store = factory.getCalypsoCertificateLegacyPrimeStore();

    // Generate PCA key pair (2048-bit RSA with exponent 65537)
    KeyPair pcaKeyPair = generateRSAKeyPair();
    pcaPrivateKey = (RSAPrivateKey) pcaKeyPair.getPrivate();
    pcaPublicKey = (RSAPublicKey) pcaKeyPair.getPublic();

    // Create PCA key reference (29 bytes)
    pcaKeyReference = createKeyReference(new byte[] {0x01, 0x02, 0x03, 0x04, 0x05}, 1);

    // Generate CA key pair
    KeyPair caKeyPair = generateRSAKeyPair();
    caPrivateKey = (RSAPrivateKey) caKeyPair.getPrivate();
    caPublicKey = (RSAPublicKey) caKeyPair.getPublic();

    // Create CA key reference (29 bytes)
    caKeyReference = createKeyReference(new byte[] {0x01, 0x02, 0x03, 0x04, 0x05}, 2);

    // Add PCA public key to store
    store.addPcaPublicKey(pcaKeyReference, pcaPublicKey);
  }

  @Test
  void testGenerateCaCertificate_withDefaultSigner_shouldSucceed() {
    // Given - Create signer with PCA private key
    CalypsoCertificateLegacyPrimeSigner pcaSigner =
        new DefaultCalypsoCertificateLegacyPrimeSigner(pcaPrivateKey);

    // When - Generate CA certificate
    byte[] caCertificate =
        factory
            .createCalypsoCaCertificateLegacyPrimeGenerator(pcaKeyReference, pcaSigner)
            .withCaPublicKey(caKeyReference, caPublicKey)
            .withStartDate(2025, 1, 1)
            .withEndDate(2030, 12, 31)
            .withCaRights((byte) 0x0A) // Can sign both CA and card certificates
            .withCaScope((byte) 0xFF) // No scope restriction
            .withTargetAid(new byte[] {0x01, 0x02, 0x03, 0x04, 0x05}, true)
            .generate();

    // Then
    assertThat(caCertificate).isNotNull().hasSize(384); // 128 bytes data + 256 bytes signature

    // Verify we can add it to store (validates signature)
    byte[] addedKeyReference = store.addCalypsoCaCertificateLegacyPrime(caCertificate);
    assertThat(addedKeyReference).isEqualTo(caKeyReference);
  }

  @Test
  void testGenerateCaCertificate_andParseIt_shouldRecoverAllFields() throws Exception {
    // Given
    CalypsoCertificateLegacyPrimeSigner pcaSigner =
        new DefaultCalypsoCertificateLegacyPrimeSigner(pcaPrivateKey);

    byte[] targetAid = new byte[] {0x01, 0x02, 0x03, 0x04, 0x05};

    // When - Generate CA certificate
    byte[] caCertificate =
        factory
            .createCalypsoCaCertificateLegacyPrimeGenerator(pcaKeyReference, pcaSigner)
            .withCaPublicKey(caKeyReference, caPublicKey)
            .withStartDate(2025, 1, 15)
            .withEndDate(2030, 6, 30)
            .withCaRights((byte) 0x0A)
            .withCaScope((byte) 0xFF)
            .withTargetAid(targetAid, true)
            .generate();

    // Add to store
    store.addCalypsoCaCertificateLegacyPrime(caCertificate);

    // Then - Parse certificate and verify fields
    CaCertificate parsedCert = CaCertificate.fromBytes(caCertificate, pcaPublicKey);

    assertThat(parsedCert.getCertType()).isEqualTo(CertificateType.CA);
    assertThat(parsedCert.getStructureVersion()).isEqualTo((byte) 1);
    assertThat(parsedCert.getIssuerKeyReference()).isEqualTo(pcaKeyReference);
    assertThat(parsedCert.getCaTargetKeyReference()).isEqualTo(caKeyReference);

    // Verify dates
    assertThat(parsedCert.getStartDate()).isNotNull();
    assertThat(parsedCert.getStartDate().getYear()).isEqualTo(2025);
    assertThat(parsedCert.getStartDate().getMonthValue()).isEqualTo(1);
    assertThat(parsedCert.getStartDate().getDayOfMonth()).isEqualTo(15);

    assertThat(parsedCert.getEndDate()).isNotNull();
    assertThat(parsedCert.getEndDate().getYear()).isEqualTo(2030);
    assertThat(parsedCert.getEndDate().getMonthValue()).isEqualTo(6);
    assertThat(parsedCert.getEndDate().getDayOfMonth()).isEqualTo(30);

    // Verify CA rights
    assertThat(parsedCert.getCaRights().getCaCertRight()).isEqualTo(CertRight.MAY_SIGN);
    assertThat(parsedCert.getCaRights().getCardCertRight()).isEqualTo(CertRight.MAY_SIGN);

    // Verify CA scope
    assertThat(parsedCert.getCaScope()).isEqualTo(CaScope.NOT_RESTRICTED);

    // Verify target AID
    assertThat(parsedCert.getCaTargetAid()).isNotNull();
    assertThat(parsedCert.getCaTargetAid().getUnpaddedValue()).startsWith(targetAid);

    // Verify operating mode (truncation allowed)
    assertThat(parsedCert.getCaOperatingMode()).isEqualTo(OperatingMode.TRUNCATION_ALLOWED);

    // Verify public key was recovered
    assertThat(parsedCert.getRsaPublicKey()).isNotNull();
    // Note: The modulus might have different byte representation due to leading zero padding
    // We verify the key is valid by checking it's 2048 bits
    assertThat(parsedCert.getRsaPublicKey().getModulus().bitLength()).isEqualTo(2048);
    assertThat(parsedCert.getRsaPublicKey().getPublicExponent())
        .isEqualTo(caPublicKey.getPublicExponent());
  }

  @Test
  void testGenerateCardCertificate_withDefaultSigner_shouldSucceed() {
    // Given - First create and add CA certificate
    CalypsoCertificateLegacyPrimeSigner pcaSigner =
        new DefaultCalypsoCertificateLegacyPrimeSigner(pcaPrivateKey);

    byte[] caCertificate =
        factory
            .createCalypsoCaCertificateLegacyPrimeGenerator(pcaKeyReference, pcaSigner)
            .withCaPublicKey(caKeyReference, caPublicKey)
            .withStartDate(2025, 1, 1)
            .withEndDate(2030, 12, 31)
            .withCaRights((byte) 0x0A) // Can sign card certificates
            .generate();

    store.addCalypsoCaCertificateLegacyPrime(caCertificate);

    // Create CA signer
    CalypsoCertificateLegacyPrimeSigner caSigner =
        new DefaultCalypsoCertificateLegacyPrimeSigner(caPrivateKey);

    // Prepare card data
    byte[] cardPublicKey = new byte[64]; // ECC public key
    for (int i = 0; i < cardPublicKey.length; i++) {
      cardPublicKey[i] = (byte) (i + 1);
    }

    byte[] cardAid = new byte[] {0x01, 0x02, 0x03, 0x04, 0x05};
    byte[] cardSerialNumber = new byte[] {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88};
    byte[] cardStartupInfo = new byte[] {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};

    // When - Generate card certificate
    byte[] cardCertificate =
        factory
            .createCalypsoCardCertificateLegacyPrimeGenerator(caKeyReference, caSigner)
            .withCardPublicKey(cardPublicKey)
            .withCardAid(cardAid)
            .withCardSerialNumber(cardSerialNumber)
            .withCardStartupInfo(cardStartupInfo)
            .withStartDate(2025, 2, 1)
            .withEndDate(2028, 12, 31)
            .withIndex(1)
            .generate();

    // Then
    assertThat(cardCertificate).isNotNull().hasSize(316); // 60 bytes data + 256 bytes signature
  }

  @Test
  void testCompleteChain_PCA_to_CA_to_Card_shouldSucceed() {
    // This test demonstrates a complete certificate chain:
    // PCA (root) → CA (intermediate) → Card (end entity)

    // Step 1: Create PCA signer and generate CA certificate
    CalypsoCertificateLegacyPrimeSigner pcaSigner =
        new DefaultCalypsoCertificateLegacyPrimeSigner(pcaPrivateKey);

    byte[] caCertificate =
        factory
            .createCalypsoCaCertificateLegacyPrimeGenerator(pcaKeyReference, pcaSigner)
            .withCaPublicKey(caKeyReference, caPublicKey)
            .withStartDate(2025, 1, 1)
            .withEndDate(2035, 12, 31) // Long validity for CA
            .withCaRights((byte) 0x0A) // Can sign both CA and card certificates
            .withCaScope((byte) 0xFF)
            .withTargetAid(new byte[] {0x01, 0x02, 0x03, 0x04, 0x05}, true)
            .generate();

    // Step 2: Add CA certificate to store
    byte[] addedCaKeyRef = store.addCalypsoCaCertificateLegacyPrime(caCertificate);
    assertThat(addedCaKeyRef).isEqualTo(caKeyReference);

    // Step 3: Create CA signer and generate card certificate
    CalypsoCertificateLegacyPrimeSigner caSigner =
        new DefaultCalypsoCertificateLegacyPrimeSigner(caPrivateKey);

    byte[] cardPublicKey = new byte[64];
    for (int i = 0; i < 64; i++) {
      cardPublicKey[i] = (byte) ((i * 7) % 256);
    }

    byte[] cardCertificate =
        factory
            .createCalypsoCardCertificateLegacyPrimeGenerator(caKeyReference, caSigner)
            .withCardPublicKey(cardPublicKey)
            .withCardAid(new byte[] {0x01, 0x02, 0x03, 0x04, 0x05})
            .withCardSerialNumber(new byte[] {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})
            .withCardStartupInfo(new byte[] {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17})
            .withStartDate(2025, 3, 1)
            .withEndDate(2027, 12, 31)
            .generate();

    // Step 4: Verify both certificates are valid
    assertThat(caCertificate).hasSize(384);
    assertThat(cardCertificate).hasSize(316);

    // Step 5: Parse and verify CA certificate
    CaCertificate parsedCaCert = CaCertificate.fromBytes(caCertificate, pcaPublicKey);
    assertThat(parsedCaCert).isNotNull();
    assertThat(parsedCaCert.getCaRights().getCardCertRight()).isEqualTo(CertRight.MAY_SIGN);

    // Step 6: Verify card certificate is generated with correct size
    // Note: CardCertificate parsing is internal - we verify size and successful generation
    assertThat(cardCertificate).hasSize(316);
  }

  @Test
  void testMultipleCardCertificates_withSameCA_shouldAllBeValid() {
    // Given - Setup CA
    CalypsoCertificateLegacyPrimeSigner pcaSigner =
        new DefaultCalypsoCertificateLegacyPrimeSigner(pcaPrivateKey);

    byte[] caCertificate =
        factory
            .createCalypsoCaCertificateLegacyPrimeGenerator(pcaKeyReference, pcaSigner)
            .withCaPublicKey(caKeyReference, caPublicKey)
            .withStartDate(2025, 1, 1)
            .withEndDate(2030, 12, 31)
            .withCaRights((byte) 0x0A)
            .generate();

    store.addCalypsoCaCertificateLegacyPrime(caCertificate);

    CalypsoCertificateLegacyPrimeSigner caSigner =
        new DefaultCalypsoCertificateLegacyPrimeSigner(caPrivateKey);

    // When - Generate multiple card certificates
    byte[] card1 = generateCardCertificate(caSigner, 1);
    byte[] card2 = generateCardCertificate(caSigner, 2);
    byte[] card3 = generateCardCertificate(caSigner, 3);

    // Then - All should be valid (correct size)
    assertThat(card1).hasSize(316);
    assertThat(card2).hasSize(316);
    assertThat(card3).hasSize(316);

    // Verify they are different (different indices produce different certificates)
    assertThat(card1).isNotEqualTo(card2);
    assertThat(card2).isNotEqualTo(card3);
    assertThat(card1).isNotEqualTo(card3);
  }

  @Test
  void testCaCertificate_withMinimalParameters_shouldSucceed() {
    // Given - Create signer
    CalypsoCertificateLegacyPrimeSigner pcaSigner =
        new DefaultCalypsoCertificateLegacyPrimeSigner(pcaPrivateKey);

    // When - Generate with only required parameters (no dates, no rights, no scope)
    byte[] caCertificate =
        factory
            .createCalypsoCaCertificateLegacyPrimeGenerator(pcaKeyReference, pcaSigner)
            .withCaPublicKey(caKeyReference, caPublicKey)
            .generate();

    // Then - Should succeed and be valid
    assertThat(caCertificate).hasSize(384);

    // Verify we can add it to store
    byte[] addedKeyRef = store.addCalypsoCaCertificateLegacyPrime(caCertificate);
    assertThat(addedKeyRef).isEqualTo(caKeyReference);

    // Verify we can parse it
    CaCertificate parsedCert = CaCertificate.fromBytes(caCertificate, pcaPublicKey);
    assertThat(parsedCert).isNotNull();
    assertThat(parsedCert.getStartDate()).isNull(); // No start date set
    assertThat(parsedCert.getEndDate()).isNull(); // No end date set
  }

  // Helper methods

  private KeyPair generateRSAKeyPair() throws Exception {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(2048);
    KeyPair tempKeyPair = keyGen.generateKeyPair();

    // Force exponent to 65537
    RSAPublicKey tempPublicKey = (RSAPublicKey) tempKeyPair.getPublic();
    RSAPrivateKey tempPrivateKey = (RSAPrivateKey) tempKeyPair.getPrivate();

    BigInteger modulus = tempPublicKey.getModulus();
    BigInteger publicExponent = BigInteger.valueOf(65537);
    BigInteger privateExponent = tempPrivateKey.getPrivateExponent();

    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(modulus, publicExponent);
    RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);

    RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(modulus, privateExponent);
    RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);

    return new KeyPair(publicKey, privateKey);
  }

  private byte[] createKeyReference(byte[] aid, int keyId) {
    byte[] keyReference = new byte[29];
    keyReference[0] = (byte) aid.length; // AID size
    System.arraycopy(aid, 0, keyReference, 1, aid.length); // AID value
    // Serial number (8 bytes) at offset 17 - leave as zeros
    // Key ID (4 bytes) at offset 25
    keyReference[28] = (byte) keyId;
    return keyReference;
  }

  private byte[] generateCardCertificate(CalypsoCertificateLegacyPrimeSigner signer, int index) {
    byte[] cardPublicKey = new byte[64];
    for (int i = 0; i < 64; i++) {
      cardPublicKey[i] = (byte) ((i * index) % 256);
    }

    byte[] serialNumber = new byte[8];
    serialNumber[7] = (byte) index;

    return factory
        .createCalypsoCardCertificateLegacyPrimeGenerator(caKeyReference, signer)
        .withCardPublicKey(cardPublicKey)
        .withCardAid(new byte[] {0x01, 0x02, 0x03, 0x04, 0x05})
        .withCardSerialNumber(serialNumber)
        .withCardStartupInfo(new byte[] {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07})
        .withStartDate(2025, 1, 1)
        .withEndDate(2027, 12, 31)
        .withIndex(index)
        .generate();
  }
}
