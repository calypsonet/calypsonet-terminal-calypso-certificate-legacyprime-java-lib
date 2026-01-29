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

import java.io.FileOutputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.calypsonet.terminal.calypso.certificate.legacyprime.spi.CalypsoCertificateLegacyPrimeSigner;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class DefaultCalypsoCertificateLegacyPrimeSignerTest {

  private RSAPrivateKey validPrivateKey;
  private RSAPublicKey validPublicKey;
  private byte[] testData;
  private byte[] testRecoverableData;

  @TempDir Path tempDir;

  @BeforeEach
  void setUp() throws Exception {
    // Generate a valid 2048-bit RSA key pair with exponent 65537
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(2048);
    KeyPair tempKeyPair = keyGen.generateKeyPair();

    // Force exponent to 65537
    RSAPublicKey tempPublicKey = (RSAPublicKey) tempKeyPair.getPublic();
    RSAPrivateKey tempPrivateKey = (RSAPrivateKey) tempKeyPair.getPrivate();

    BigInteger modulus = tempPublicKey.getModulus();
    BigInteger publicExponent = BigInteger.valueOf(65537);
    BigInteger privateExponent = tempPrivateKey.getPrivateExponent();

    // Recreate keys with correct exponent
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(modulus, publicExponent);
    validPublicKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);

    RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(modulus, privateExponent);
    validPrivateKey = (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);

    // Prepare test data
    testData = new byte[128]; // CA certificate data size
    for (int i = 0; i < testData.length; i++) {
      testData[i] = (byte) i;
    }

    testRecoverableData = new byte[222]; // Recoverable data size
    for (int i = 0; i < testRecoverableData.length; i++) {
      testRecoverableData[i] = (byte) (i % 256);
    }
  }

  // Constructor tests

  @Test
  void constructor_whenPrivateKeyIsValid_shouldCreateSigner() {
    // When
    CalypsoCertificateLegacyPrimeSigner signer =
        new DefaultCalypsoCertificateLegacyPrimeSigner(validPrivateKey);

    // Then
    assertThat(signer).isNotNull();
  }

  @Test
  void constructor_whenPrivateKeyIsNull_shouldThrowIllegalArgumentException() {
    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> new DefaultCalypsoCertificateLegacyPrimeSigner(null))
        .withMessageContaining("privateKey");
  }

  @Test
  void constructor_whenPrivateKeyIsNot2048Bit_shouldThrowIllegalArgumentException()
      throws Exception {
    // Given - Generate 1024-bit key
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(1024);
    KeyPair keyPair = keyGen.generateKeyPair();
    RSAPrivateKey invalidKey = (RSAPrivateKey) keyPair.getPrivate();

    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> new DefaultCalypsoCertificateLegacyPrimeSigner(invalidKey))
        .withMessageContaining("2048-bit")
        .withMessageContaining("1024-bit");
  }

  // generateSignedCertificate tests

  @Test
  void generateSignedCertificate_whenParametersAreValid_shouldReturnSignedCertificate() {
    // Given
    CalypsoCertificateLegacyPrimeSigner signer =
        new DefaultCalypsoCertificateLegacyPrimeSigner(validPrivateKey);

    // When
    byte[] signedCertificate = signer.generateSignedCertificate(testData, testRecoverableData);

    // Then
    assertThat(signedCertificate).isNotNull();
    assertThat(signedCertificate.length).isEqualTo(testData.length + 256); // data + signature

    // Verify that data is preserved
    for (int i = 0; i < testData.length; i++) {
      assertThat(signedCertificate[i]).isEqualTo(testData[i]);
    }
  }

  @Test
  void generateSignedCertificate_whenDataIsNull_shouldThrowIllegalArgumentException() {
    // Given
    CalypsoCertificateLegacyPrimeSigner signer =
        new DefaultCalypsoCertificateLegacyPrimeSigner(validPrivateKey);

    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> signer.generateSignedCertificate(null, testRecoverableData))
        .withMessageContaining("data");
  }

  @Test
  void generateSignedCertificate_whenRecoverableDataIsNull_shouldThrowIllegalArgumentException() {
    // Given
    CalypsoCertificateLegacyPrimeSigner signer =
        new DefaultCalypsoCertificateLegacyPrimeSigner(validPrivateKey);

    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> signer.generateSignedCertificate(testData, null))
        .withMessageContaining("recoverableData");
  }

  @Test
  void
      generateSignedCertificate_whenRecoverableDataIsNot222Bytes_shouldThrowIllegalArgumentException() {
    // Given
    CalypsoCertificateLegacyPrimeSigner signer =
        new DefaultCalypsoCertificateLegacyPrimeSigner(validPrivateKey);
    byte[] invalidRecoverableData = new byte[100];

    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> signer.generateSignedCertificate(testData, invalidRecoverableData))
        .withMessageContaining("recoverableData length");
  }

  @Test
  void generateSignedCertificate_shouldBeIdempotent() {
    // Given
    CalypsoCertificateLegacyPrimeSigner signer =
        new DefaultCalypsoCertificateLegacyPrimeSigner(validPrivateKey);

    // When - Generate twice with same data
    byte[] signature1 = signer.generateSignedCertificate(testData, testRecoverableData);
    byte[] signature2 = signer.generateSignedCertificate(testData, testRecoverableData);

    // Then - Should produce identical results (salt=0 means deterministic)
    assertThat(signature1).isEqualTo(signature2);
  }

  @Test
  void generateSignedCertificate_withDifferentData_shouldProduceDifferentSignatures() {
    // Given
    CalypsoCertificateLegacyPrimeSigner signer =
        new DefaultCalypsoCertificateLegacyPrimeSigner(validPrivateKey);
    byte[] differentData = testData.clone();
    differentData[0] = (byte) (differentData[0] + 1);

    // When
    byte[] signature1 = signer.generateSignedCertificate(testData, testRecoverableData);
    byte[] signature2 = signer.generateSignedCertificate(differentData, testRecoverableData);

    // Then
    assertThat(signature1).isNotEqualTo(signature2);
  }

  // fromPemString tests

  @Test
  void fromPemString_whenPemIsValid_shouldCreateSigner() throws Exception {
    // Given - Create PEM string
    StringWriter stringWriter = new StringWriter();
    try (PemWriter pemWriter = new PemWriter(stringWriter)) {
      PemObject pemObject = new PemObject("PRIVATE KEY", validPrivateKey.getEncoded());
      pemWriter.writeObject(pemObject);
    }
    String pemContent = stringWriter.toString();

    // When
    CalypsoCertificateLegacyPrimeSigner signer =
        DefaultCalypsoCertificateLegacyPrimeSigner.fromPemString(pemContent);

    // Then
    assertThat(signer).isNotNull();

    // Verify it can sign
    byte[] signature = signer.generateSignedCertificate(testData, testRecoverableData);
    assertThat(signature).isNotNull().hasSize(testData.length + 256);
  }

  @Test
  void fromPemString_whenPemIsNull_shouldThrowIllegalArgumentException() {
    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> DefaultCalypsoCertificateLegacyPrimeSigner.fromPemString(null))
        .withMessageContaining("pemContent");
  }

  @Test
  void fromPemString_whenPemIsInvalid_shouldThrowIllegalArgumentException() {
    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(
            () -> DefaultCalypsoCertificateLegacyPrimeSigner.fromPemString("invalid pem content"))
        .withMessageContaining("PEM");
  }

  // fromPemFile tests

  @Test
  void fromPemFile_whenFileIsValid_shouldCreateSigner() throws Exception {
    // Given - Create PEM file
    Path pemFile = tempDir.resolve("private-key.pem");
    try (PemWriter pemWriter = new PemWriter(Files.newBufferedWriter(pemFile))) {
      PemObject pemObject = new PemObject("PRIVATE KEY", validPrivateKey.getEncoded());
      pemWriter.writeObject(pemObject);
    }

    // When
    CalypsoCertificateLegacyPrimeSigner signer =
        DefaultCalypsoCertificateLegacyPrimeSigner.fromPemFile(pemFile.toString());

    // Then
    assertThat(signer).isNotNull();

    // Verify it can sign
    byte[] signature = signer.generateSignedCertificate(testData, testRecoverableData);
    assertThat(signature).isNotNull().hasSize(testData.length + 256);
  }

  @Test
  void fromPemFile_whenFilePathIsNull_shouldThrowIllegalArgumentException() {
    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(() -> DefaultCalypsoCertificateLegacyPrimeSigner.fromPemFile(null))
        .withMessageContaining("pemFilePath");
  }

  @Test
  void fromPemFile_whenFileDoesNotExist_shouldThrowIllegalArgumentException() {
    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(
            () ->
                DefaultCalypsoCertificateLegacyPrimeSigner.fromPemFile(
                    tempDir.resolve("nonexistent.pem").toString()))
        .withMessageContaining("Failed to read PEM file");
  }

  // fromKeyStore tests

  @Test
  void fromKeyStore_whenKeyStoreIsValid_shouldCreateSigner() throws Exception {
    // Given - Create KeyStore with key
    KeyStore keyStore = KeyStore.getInstance("PKCS12");
    keyStore.load(null, null);

    // Create a self-signed certificate for the key entry
    X509Certificate cert = createSelfSignedCertificate(validPublicKey, validPrivateKey);

    keyStore.setKeyEntry(
        "test-key", validPrivateKey, "key-password".toCharArray(), new Certificate[] {cert});

    // When
    CalypsoCertificateLegacyPrimeSigner signer =
        DefaultCalypsoCertificateLegacyPrimeSigner.fromKeyStore(
            keyStore, "test-key", "key-password".toCharArray());

    // Then
    assertThat(signer).isNotNull();

    // Verify it can sign
    byte[] signature = signer.generateSignedCertificate(testData, testRecoverableData);
    assertThat(signature).isNotNull().hasSize(testData.length + 256);
  }

  @Test
  void fromKeyStore_whenKeyStoreIsNull_shouldThrowIllegalArgumentException() {
    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(
            () ->
                DefaultCalypsoCertificateLegacyPrimeSigner.fromKeyStore(
                    null, "alias", "password".toCharArray()))
        .withMessageContaining("keyStore");
  }

  @Test
  void fromKeyStore_whenAliasIsNull_shouldThrowIllegalArgumentException() throws Exception {
    // Given
    KeyStore keyStore = KeyStore.getInstance("PKCS12");
    keyStore.load(null, null);

    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(
            () ->
                DefaultCalypsoCertificateLegacyPrimeSigner.fromKeyStore(
                    keyStore, null, "password".toCharArray()))
        .withMessageContaining("alias");
  }

  @Test
  void fromKeyStore_whenAliasDoesNotExist_shouldThrowIllegalArgumentException() throws Exception {
    // Given
    KeyStore keyStore = KeyStore.getInstance("PKCS12");
    keyStore.load(null, null);

    // When & Then
    assertThatIllegalArgumentException()
        .isThrownBy(
            () ->
                DefaultCalypsoCertificateLegacyPrimeSigner.fromKeyStore(
                    keyStore, "nonexistent", "password".toCharArray()))
        .withMessageContaining("KeyStore")
        .withCauseInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void fromKeyStore_shouldWorkWithRealKeyStoreFile() throws Exception {
    // Given - Create a real PKCS12 file
    Path keyStoreFile = tempDir.resolve("test-keystore.p12");

    KeyStore keyStore = KeyStore.getInstance("PKCS12");
    keyStore.load(null, null);

    X509Certificate cert = createSelfSignedCertificate(validPublicKey, validPrivateKey);
    keyStore.setKeyEntry(
        "my-key", validPrivateKey, "key-password".toCharArray(), new Certificate[] {cert});

    try (FileOutputStream fos = new FileOutputStream(keyStoreFile.toFile())) {
      keyStore.store(fos, "store-password".toCharArray());
    }

    // When - Load from file
    KeyStore loadedKeyStore = KeyStore.getInstance("PKCS12");
    try (java.io.FileInputStream fis = new java.io.FileInputStream(keyStoreFile.toFile())) {
      loadedKeyStore.load(fis, "store-password".toCharArray());
    }

    CalypsoCertificateLegacyPrimeSigner signer =
        DefaultCalypsoCertificateLegacyPrimeSigner.fromKeyStore(
            loadedKeyStore, "my-key", "key-password".toCharArray());

    // Then
    assertThat(signer).isNotNull();

    // Verify it can sign
    byte[] signature = signer.generateSignedCertificate(testData, testRecoverableData);
    assertThat(signature).isNotNull().hasSize(testData.length + 256);
  }

  // Helper method to create a self-signed certificate
  private X509Certificate createSelfSignedCertificate(
      RSAPublicKey publicKey, RSAPrivateKey privateKey) throws Exception {
    long now = System.currentTimeMillis();
    Date startDate = new Date(now);
    Date endDate = new Date(now + 365L * 24 * 60 * 60 * 1000); // 1 year

    X500Name issuer = new X500Name("CN=Test Certificate");
    BigInteger serialNumber = BigInteger.valueOf(now);

    SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());

    X509v3CertificateBuilder certBuilder =
        new X509v3CertificateBuilder(
            issuer, serialNumber, startDate, endDate, issuer, publicKeyInfo);

    ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(privateKey);

    return new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));
  }
}
