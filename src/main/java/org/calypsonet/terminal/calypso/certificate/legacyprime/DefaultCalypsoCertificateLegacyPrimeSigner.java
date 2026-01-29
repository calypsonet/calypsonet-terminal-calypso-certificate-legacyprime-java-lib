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

import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.ISO9796d2PSSSigner;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.calypsonet.terminal.calypso.certificate.legacyprime.spi.CalypsoCertificateLegacyPrimeSigner;
import org.eclipse.keyple.core.util.Assert;

/**
 * Default implementation of {@link CalypsoCertificateLegacyPrimeSigner}.
 *
 * <p>This class provides a reference implementation for signing Calypso Prime Legacy certificates
 * using ISO/IEC 9796-2 PSS (Probabilistic Signature Scheme) with message recovery.
 *
 * <p>The signer uses RSA 2048-bit private keys with a public exponent of 65537 to generate
 * signatures compatible with the Calypso Prime Legacy specification.
 *
 * <p><b>Important Security Notes:</b>
 *
 * <ul>
 *   <li>This implementation keeps the private key in memory. For production use cases involving
 *       sensitive keys, consider implementing a custom signer that delegates to a Hardware Security
 *       Module (HSM) or secure key storage.
 *   <li>The private key is stored as a final field and cannot be changed after construction.
 *   <li>This class is thread-safe as long as the underlying BouncyCastle implementation is
 *       thread-safe. For concurrent usage, consider creating separate signer instances per thread.
 * </ul>
 *
 * <p><b>Usage Examples:</b>
 *
 * <pre>{@code
 * // From an existing RSAPrivateKey
 * RSAPrivateKey privateKey = ...;
 * CalypsoCertificateLegacyPrimeSigner signer =
 *     new DefaultCalypsoCertificateLegacyPrimeSigner(privateKey);
 *
 * // From a PEM file
 * CalypsoCertificateLegacyPrimeSigner signer =
 *     DefaultCalypsoCertificateLegacyPrimeSigner.fromPemFile("private-key.pem");
 *
 * // From a KeyStore
 * KeyStore keyStore = KeyStore.getInstance("PKCS12");
 * try (FileInputStream fis = new FileInputStream("keystore.p12")) {
 *     keyStore.load(fis, "password".toCharArray());
 * }
 * CalypsoCertificateLegacyPrimeSigner signer =
 *     DefaultCalypsoCertificateLegacyPrimeSigner.fromKeyStore(
 *         keyStore, "key-alias", "key-password".toCharArray());
 * }</pre>
 *
 * @since 0.1.0
 */
public final class DefaultCalypsoCertificateLegacyPrimeSigner
    implements CalypsoCertificateLegacyPrimeSigner {

  private final RSAPrivateKey privateKey;

  /**
   * Creates a new signer with the provided RSA private key.
   *
   * <p>The private key must be a 2048-bit RSA key. The corresponding public key must have an
   * exponent of 65537.
   *
   * @param privateKey The RSA private key to use for signing (must not be null, must be 2048-bit).
   * @throws IllegalArgumentException If the private key is null or invalid (wrong size or
   *     exponent).
   * @since 0.1.0
   */
  public DefaultCalypsoCertificateLegacyPrimeSigner(RSAPrivateKey privateKey) {
    Assert.getInstance().notNull(privateKey, "privateKey");
    validatePrivateKey(privateKey);
    this.privateKey = privateKey;
  }

  /**
   * Creates a signer from a PEM-encoded private key file.
   *
   * <p>The PEM file should contain a private key in PKCS#8 format (-----BEGIN PRIVATE KEY-----).
   *
   * @param pemFilePath The path to the PEM file containing the private key.
   * @return A new signer instance.
   * @throws IllegalArgumentException If the file cannot be read, is not a valid PEM file, or does
   *     not contain a valid RSA private key.
   * @since 0.1.0
   */
  public static DefaultCalypsoCertificateLegacyPrimeSigner fromPemFile(String pemFilePath) {
    Assert.getInstance().notNull(pemFilePath, "pemFilePath");
    try (FileInputStream fis = new FileInputStream(pemFilePath)) {
      byte[] pemBytes = new byte[fis.available()];
      fis.read(pemBytes);
      String pemContent = new String(pemBytes);
      return fromPemString(pemContent);
    } catch (IOException e) {
      throw new IllegalArgumentException("Failed to read PEM file: " + pemFilePath, e);
    }
  }

  /**
   * Creates a signer from a PEM-encoded private key string.
   *
   * <p>The PEM string should contain a private key in PKCS#8 format (-----BEGIN PRIVATE KEY-----).
   *
   * @param pemContent The PEM-encoded private key string.
   * @return A new signer instance.
   * @throws IllegalArgumentException If the PEM string is not valid or does not contain a valid RSA
   *     private key.
   * @since 0.1.0
   */
  public static DefaultCalypsoCertificateLegacyPrimeSigner fromPemString(String pemContent) {
    Assert.getInstance().notNull(pemContent, "pemContent");
    try (PemReader pemReader = new PemReader(new StringReader(pemContent))) {
      PemObject pemObject = pemReader.readPemObject();
      if (pemObject == null) {
        throw new IllegalArgumentException("No PEM object found in content");
      }

      PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pemObject.getContent());
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

      if (!(privateKey instanceof RSAPrivateKey)) {
        throw new IllegalArgumentException("PEM content does not contain an RSA private key");
      }

      return new DefaultCalypsoCertificateLegacyPrimeSigner((RSAPrivateKey) privateKey);
    } catch (Exception e) {
      throw new IllegalArgumentException("Failed to parse PEM private key", e);
    }
  }

  /**
   * Creates a signer from a KeyStore.
   *
   * <p>Extracts the private key from the specified KeyStore entry.
   *
   * @param keyStore The KeyStore containing the private key (must not be null).
   * @param alias The alias of the key entry in the KeyStore (must not be null).
   * @param password The password to access the key (may be null if no password is required).
   * @return A new signer instance.
   * @throws IllegalArgumentException If the KeyStore, alias is null, the entry does not exist, or
   *     does not contain a valid RSA private key.
   * @since 0.1.0
   */
  public static DefaultCalypsoCertificateLegacyPrimeSigner fromKeyStore(
      KeyStore keyStore, String alias, char[] password) {
    Assert.getInstance().notNull(keyStore, "keyStore").notNull(alias, "alias");

    try {
      if (!keyStore.containsAlias(alias)) {
        throw new IllegalArgumentException("Alias '" + alias + "' not found in KeyStore");
      }

      PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password);
      if (privateKey == null) {
        throw new IllegalArgumentException(
            "No private key found for alias '" + alias + "' in KeyStore");
      }

      if (!(privateKey instanceof RSAPrivateKey)) {
        throw new IllegalArgumentException(
            "Key at alias '" + alias + "' is not an RSA private key");
      }

      return new DefaultCalypsoCertificateLegacyPrimeSigner((RSAPrivateKey) privateKey);
    } catch (Exception e) {
      throw new IllegalArgumentException("Failed to load private key from KeyStore", e);
    }
  }

  /**
   * Validates that the private key is a 2048-bit RSA key with a public exponent of 65537.
   *
   * @param privateKey The private key to validate.
   * @throws IllegalArgumentException If the key is invalid.
   */
  private static void validatePrivateKey(RSAPrivateKey privateKey) {
    // Check modulus bit length
    int bitLength = privateKey.getModulus().bitLength();
    if (bitLength != CertificateConstants.RSA_MODULUS_BIT_LENGTH) {
      throw new IllegalArgumentException(
          "Private key must be "
              + CertificateConstants.RSA_MODULUS_BIT_LENGTH
              + "-bit, but is "
              + bitLength
              + "-bit");
    }

    // Note: We cannot verify the public exponent from the private key alone.
    // The user must ensure the corresponding public key has exponent 65537.
  }

  /**
   * {@inheritDoc}
   *
   * <p>This implementation uses ISO/IEC 9796-2 PSS (Probabilistic Signature Scheme) with:
   *
   * <ul>
   *   <li>Digest algorithm: SHA-256
   *   <li>Salt length: 0 (deterministic for the same input)
   *   <li>Message recovery: enabled (recoverable data is embedded in the signature)
   *   <li>Signature size: 256 bytes (RSA 2048-bit)
   * </ul>
   *
   * <p>The signature is generated over the concatenation of the recoverable data and the
   * non-recoverable data, following the ISO/IEC 9796-2 standard.
   *
   * @param data The non-recoverable data to be included in the final certificate (must not be
   *     null).
   * @param recoverableData The recoverable data to be embedded in the signature (must not be null,
   *     must be 222 bytes).
   * @return The signed certificate as a byte array (data + signature).
   * @throws CertificateSigningException If an error occurs during the signing process.
   * @since 0.1.0
   */
  @Override
  public byte[] generateSignedCertificate(byte[] data, byte[] recoverableData) {
    Assert.getInstance()
        .notNull(data, "data")
        .notNull(recoverableData, "recoverableData")
        .isEqual(
            recoverableData.length,
            CertificateConstants.RECOVERABLE_DATA_SIZE,
            "recoverableData length");

    try {
      // Create RSA key parameters from private key
      RSAKeyParameters privParams =
          new RSAKeyParameters(true, privateKey.getModulus(), privateKey.getPrivateExponent());

      // Create ISO9796-2 PSS signer with SHA-256, salt=0, fullMessage=true
      ISO9796d2PSSSigner signer =
          new ISO9796d2PSSSigner(new RSAEngine(), new SHA256Digest(), 0, true);

      // Initialize signer in signature mode (true = signing)
      signer.init(true, privParams);

      // Update with recoverable data (will be embedded in signature)
      // Note: For signing, we use update(), not updateWithRecoveredMessage()
      signer.update(recoverableData, 0, recoverableData.length);

      // Update with non-recoverable data
      signer.update(data, 0, data.length);

      // Generate signature
      byte[] signature = signer.generateSignature();

      // Verify signature size
      if (signature.length != CertificateConstants.RSA_SIGNATURE_SIZE) {
        throw new CertificateSigningException(
            "Expected signature size "
                + CertificateConstants.RSA_SIGNATURE_SIZE
                + " bytes, but got "
                + signature.length
                + " bytes");
      }

      // Concatenate data + signature
      byte[] signedCertificate = new byte[data.length + signature.length];
      System.arraycopy(data, 0, signedCertificate, 0, data.length);
      System.arraycopy(signature, 0, signedCertificate, data.length, signature.length);

      return signedCertificate;

    } catch (Exception e) {
      if (e instanceof CertificateSigningException) {
        throw (CertificateSigningException) e;
      }
      throw new CertificateSigningException("Failed to generate certificate signature", e);
    }
  }
}
