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

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.time.LocalDate;
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

  /**
   * Decodes a BCD-encoded date (YYYYMMDD) into a {@link LocalDate}.
   *
   * @param bcdDate The 4-byte BCD-encoded date.
   * @return The corresponding {@link LocalDate}, or {@code null} if the input represents a null
   *     date (all zeros).
   * @since 0.1.0
   */
  static LocalDate decodeDateBcd(byte[] bcdDate) {
    Assert.getInstance().notNull(bcdDate, "bcdDate").isEqual(bcdDate.length, 4, "bcdDate length");

    // Check for null date (00000000h)
    boolean allZeros = true;
    for (byte b : bcdDate) {
      if (b != 0) {
        allZeros = false;
        break;
      }
    }
    if (allZeros) {
      return null;
    }

    int year =
        ((bcdDate[0] >> 4) & 0x0F) * 1000
            + (bcdDate[0] & 0x0F) * 100
            + ((bcdDate[1] >> 4) & 0x0F) * 10
            + (bcdDate[1] & 0x0F);
    int month = ((bcdDate[2] >> 4) & 0x0F) * 10 + (bcdDate[2] & 0x0F);
    int day = ((bcdDate[3] >> 4) & 0x0F) * 10 + (bcdDate[3] & 0x0F);

    return LocalDate.of(year, month, day);
  }
}
