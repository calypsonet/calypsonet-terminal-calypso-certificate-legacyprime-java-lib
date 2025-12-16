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

import static org.calypsonet.terminal.calypso.certificate.legacyprime.CertificateConstants.RSA_MODULUS_SIZE;
import static org.calypsonet.terminal.calypso.certificate.legacyprime.CertificateConstants.RSA_SIGNATURE_SIZE;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.ISO9796d2PSSSigner;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.eclipse.keyple.core.util.Assert;

/**
 * Utility class containing common methods for certificate generation and manipulation.
 *
 * <p>This class provides helper methods that are shared across different certificate generator
 * implementations to avoid code duplication.
 *
 * @since 0.1.0
 */
final class CertificateUtils {

  static {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  /**
   * Private constructor to prevent instantiation.
   *
   * @since 0.1.0
   */
  private CertificateUtils() {
    // Utility class
  }

  /**
   * Validates that the provided RSA public key is a valid 2048-bit key with an exponent of 65537.
   *
   * @param rsaPublicKey The RSA public key to validate.
   * @throws IllegalArgumentException if the key is not a 2048-bit RSA key or if the exponent is not
   *     65537.
   * @since 0.1.0
   */
  static void checkRSA2048PublicKey(RSAPublicKey rsaPublicKey) {
    Assert.getInstance()
        .notNull(rsaPublicKey, "rsaPublicKey")
        .isEqual(
            rsaPublicKey.getModulus().bitLength(),
            CertificateConstants.RSA_MODULUS_BIT_LENGTH,
            "RSA public key modulus bit length")
        .isEqual(
            rsaPublicKey.getPublicExponent().intValue(),
            CertificateConstants.RSA_PUBLIC_EXPONENT,
            "RSA public key exponent");
  }

  /**
   * Creates a 2048-bit RSA public key with a public exponent of 65537 from the provided modulus
   * value.
   *
   * @param modulus A 256-byte array representing the modulus value.
   * @return A non-null {@link RSAPublicKey} instance.
   * @throws IllegalArgumentException if the provided modulus is invalid or if an error occurred
   *     during the cryptographic operations.
   * @since 0.1.0
   */
  static RSAPublicKey generateRSAPublicKeyFromModulus(byte[] modulus) {
    try {
      BigInteger modulusBigInt = new BigInteger(1, modulus);
      BigInteger publicExponent = BigInteger.valueOf(CertificateConstants.RSA_PUBLIC_EXPONENT);

      RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulusBigInt, publicExponent);
      KeyFactory keyFactory = KeyFactory.getInstance(CertificateConstants.KEY_ALGORITHM_RSA);
      return (RSAPublicKey) keyFactory.generatePublic(keySpec);
    } catch (Exception e) {
      throw new IllegalArgumentException("Failed to create RSA public key from modulus", e);
    }
  }

  /**
   * Verifies a CA certificate signature and recovers the CA's RSA public key using ISO/IEC 9796-2
   * message recovery.
   *
   * <p>This method performs two operations:
   *
   * <ol>
   *   <li>Verifies the CA certificate signature using the issuer's RSA public key
   *   <li>Recovers the CA's RSA modulus by combining the 34-byte public key header (transmitted in
   *       clear) with the 222 bytes of modulus data recovered from the signature block
   * </ol>
   *
   * <p>The signature verification and message recovery follow the ISO/IEC 9796-2 PSS (Probabilistic
   * Signature Scheme) standard with SHA-256 digest.
   *
   * @param caCertificate The complete CA certificate (290 bytes).
   * @param caPublicKeyHeader The first 34 bytes of the CA's RSA modulus, transmitted in clear.
   * @param issuerPublicKey The RSA public key (2048-bit) of the certificate issuer, used to verify
   *     the signature and recover the remaining modulus bytes.
   * @return A non-null 2048-bit RSA public key with exponent 65537, reconstructed from the header
   *     and recovered data.
   * @throws IllegalArgumentException if any parameter is null, has invalid length, or if the
   *     issuerPublicKey is not a valid 2048-bit RSA key.
   * @throws CertificateConsistencyException if signature verification fails or message recovery
   *     encounters an error.
   * @since 0.1.0
   */
  static RSAPublicKey checkCaCertificateSignatureAndRecoverRsaPublicKey(
      byte[] caCertificate, byte[] caPublicKeyHeader, RSAPublicKey issuerPublicKey) {
    Assert.getInstance()
        .notNull(caCertificate, "caCertificate")
        .isEqual(
            caCertificate.length, CertificateConstants.CA_CERTIFICATE_SIZE, "caCertificate.length")
        .notNull(caPublicKeyHeader, "caPublicKeyHeader")
        .isEqual(
            caPublicKeyHeader.length,
            CertificateConstants.PUBLIC_KEY_HEADER_SIZE,
            "caPublicKeyHeader.length");
    checkRSA2048PublicKey(issuerPublicKey);

    // check signature and recover data according to ISO/IEC 9796-2
    byte[] recoveredData =
        checkCaCertificateSignatureAndRecoverData(caCertificate, issuerPublicKey);

    // Combines the recovered data and the header transmitted in clear to create the CA public key
    byte[] caPublicKeyModulus = new byte[RSA_MODULUS_SIZE];
    System.arraycopy(caPublicKeyHeader, 0, caPublicKeyModulus, 0, caPublicKeyHeader.length);
    System.arraycopy(
        recoveredData, 0, caPublicKeyModulus, caPublicKeyHeader.length, recoveredData.length);
    return CertificateUtils.generateRSAPublicKeyFromModulus(caPublicKeyModulus);
  }

  /**
   * Verifies a CA certificate signature and recovers embedded data using ISO/IEC 9796-2 message
   * recovery with PSS.
   *
   * <p>This method implements the ISO/IEC 9796-2 signature scheme with message recovery:
   *
   * <ol>
   *   <li>Extracts the 256-byte signature block from the end of the certificate
   *   <li>Performs PSS signature verification with SHA-256 digest and message recovery
   *   <li>Updates the signer with the certificate data (excluding the signature)
   *   <li>Verifies the signature validity
   * </ol>
   *
   * <p>The recovered message contains 222 bytes of the CA's RSA modulus that were embedded in the
   * signature during signing.
   *
   * @param certificate The complete CA certificate containing data and signature.
   * @param issuerPublicKey The issuer's RSA public key used for signature verification.
   * @return A 222-byte array containing the recovered modulus data.
   * @throws CertificateConsistencyException if signature verification fails or if an error occurs
   *     during message recovery.
   */
  private static byte[] checkCaCertificateSignatureAndRecoverData(
      byte[] certificate, RSAPublicKey issuerPublicKey) throws CertificateConsistencyException {
    RSAKeyParameters pubParams =
        new RSAKeyParameters(
            false, issuerPublicKey.getModulus(), issuerPublicKey.getPublicExponent());

    ISO9796d2PSSSigner pssSign =
        new ISO9796d2PSSSigner(new RSAEngine(), new SHA256Digest(), 0, true);

    pssSign.init(false, pubParams);

    try {
      pssSign.updateWithRecoveredMessage(
          Arrays.copyOfRange(
              certificate, certificate.length - RSA_SIGNATURE_SIZE, certificate.length));

      pssSign.update(certificate, 0, certificate.length - RSA_SIGNATURE_SIZE);

      byte[] signature =
          Arrays.copyOfRange(
              certificate, certificate.length - RSA_SIGNATURE_SIZE, certificate.length);
      if (!pssSign.verifySignature(signature)) {
        throw new CertificateConsistencyException("Challenge PSS certificate verification failed");
      }

      return pssSign.getRecoveredMessage();
    } catch (InvalidCipherTextException e) {
      throw new CertificateConsistencyException(e.getMessage(), e);
    } catch (RuntimeException e) {
      throw new CertificateConsistencyException(
          "Certificate signature verification failed: " + e.getMessage(), e);
    }
  }

  /**
   * Encodes a date in BCD format (YYYYMMDD).
   *
   * @param year The year (0-9999).
   * @param month The month (1-99).
   * @param day The day (1-99).
   * @return The encoded date (4 bytes).
   * @since 0.1.0
   */
  static byte[] encodeDateBcd(int year, int month, int day) {
    byte[] date = new byte[4];
    date[0] = (byte) ((year / 1000) << 4 | (year / 100) % 10);
    date[1] = (byte) ((year / 10) % 10 << 4 | year % 10);
    date[2] = (byte) ((month / 10) << 4 | month % 10);
    date[3] = (byte) ((day / 10) << 4 | day % 10);
    return date;
  }
}
