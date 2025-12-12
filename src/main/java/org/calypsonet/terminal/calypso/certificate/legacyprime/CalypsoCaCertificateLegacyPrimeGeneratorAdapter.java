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

import java.security.interfaces.RSAPublicKey;
import org.calypsonet.terminal.calypso.certificate.legacyprime.spi.CalypsoCertificateLegacyPrimeSigner;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.HexUtil;

/**
 * Adapter implementation of {@link CalypsoCaCertificateLegacyPrimeGenerator}.
 *
 * <p>This class provides a builder pattern for creating Calypso Prime Legacy CA certificates with
 * configurable parameters.
 *
 * @since 0.1.0
 */
final class CalypsoCaCertificateLegacyPrimeGeneratorAdapter
    implements CalypsoCaCertificateLegacyPrimeGenerator {

  private final CalypsoCertificateLegacyPrimeStoreAdapter store;
  private final byte[] issuerPublicKeyReference;
  private final CalypsoCertificateLegacyPrimeSigner signer;
  private final CaCertificate.Builder certificateBuilder;

  private byte[] caPublicKeyReference;
  private boolean isAidTruncated;

  /**
   * Creates a new generator instance.
   *
   * @param store The store containing the issuer certificates.
   * @param issuerPublicKeyReference The reference to the issuer's public key.
   * @param signer The signer to use for certificate signing.
   * @since 0.1.0
   */
  CalypsoCaCertificateLegacyPrimeGeneratorAdapter(
      CalypsoCertificateLegacyPrimeStoreAdapter store,
      byte[] issuerPublicKeyReference,
      CalypsoCertificateLegacyPrimeSigner signer) {
    this.store = store;
    this.issuerPublicKeyReference = issuerPublicKeyReference.clone();
    this.signer = signer;
    // Initialize the certificate builder with known values
    this.certificateBuilder =
        CaCertificate.builder()
            .certType((byte) 0x90)
            .structureVersion((byte) 0x01)
            .issuerKeyReference(issuerPublicKeyReference);
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CalypsoCaCertificateLegacyPrimeGenerator withCaPublicKey(
      byte[] caPublicKeyReference, RSAPublicKey caPublicKey) {
    Assert.getInstance()
        .notNull(caPublicKeyReference, "caPublicKeyReference")
        .isEqual(caPublicKeyReference.length, 29, "caPublicKeyReference length")
        .notNull(caPublicKey, "caPublicKey")
        .isEqual(caPublicKey.getModulus().bitLength(), 2048, "CA public key modulus bit length")
        .isEqual(caPublicKey.getPublicExponent().intValue(), 65537, "CA public key exponent");

    this.caPublicKeyReference = caPublicKeyReference.clone();
    certificateBuilder.caTargetKeyReference(caPublicKeyReference).rsaPublicKey(caPublicKey);
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CalypsoCaCertificateLegacyPrimeGenerator withStartDate(int year, int month, int day) {
    Assert.getInstance()
        .isInRange(year, 0, 9999, "year")
        .isInRange(month, 1, 99, "month")
        .isInRange(day, 1, 99, "day");

    certificateBuilder.startDate(encodeDateBcd(year, month, day));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CalypsoCaCertificateLegacyPrimeGenerator withEndDate(int year, int month, int day) {
    Assert.getInstance()
        .isInRange(year, 0, 9999, "year")
        .isInRange(month, 1, 99, "month")
        .isInRange(day, 1, 99, "day");

    certificateBuilder.endDate(encodeDateBcd(year, month, day));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CalypsoCaCertificateLegacyPrimeGenerator withTargetAid(byte[] aid, boolean isTruncated) {
    Assert.getInstance().notNull(aid, "aid").isInRange(aid.length, 5, 16, "aid length");

    // Check if AID contains only zero bytes
    boolean allZeros = true;
    for (byte b : aid) {
      if (b != 0) {
        allZeros = false;
        break;
      }
    }

    Assert.getInstance().isTrue(!allZeros, "AID cannot contain only zero bytes");

    // Prepare padded AID value
    byte caTargetAidSize = (byte) aid.length;
    byte[] caTargetAidValue = new byte[16];
    System.arraycopy(aid, 0, caTargetAidValue, 0, aid.length);

    certificateBuilder
        .caTargetAidSize(caTargetAidSize)
        .caTargetAidValue(caTargetAidValue)
        .caOperatingMode(isTruncated ? (byte) 1 : (byte) 0);

    this.isAidTruncated = isTruncated;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CalypsoCaCertificateLegacyPrimeGenerator withCaRights(byte caRights) {
    // Check that bits b7-b4 are 0 (RFU)
    if ((caRights & 0xF0) != 0) {
      throw new IllegalArgumentException("CA rights bits b7-b4 must be 0 (RFU)");
    }
    // Check that bits b3-b2 and b1-b0 don't have value %11 (RFU)
    int cardCertRight = (caRights >> 2) & 0x03;
    int caCertRight = caRights & 0x03;
    if (cardCertRight == 0x03 || caCertRight == 0x03) {
      throw new IllegalArgumentException("CA rights value %11 is reserved for future use");
    }

    certificateBuilder.caRights(caRights);
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CalypsoCaCertificateLegacyPrimeGenerator withCaScope(byte caScope) {
    // Check that the value is valid
    if (caScope != 0x00 && caScope != 0x01 && caScope != (byte) 0xFF) {
      throw new IllegalArgumentException(
          "CA scope must be 0x00 (not specified), 0x01 (limited), or 0xFF (full)");
    }

    certificateBuilder.caScope(caScope);
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public byte[] generate() {
    // Validate required parameters
    if (caPublicKeyReference == null) {
      throw new IllegalStateException("CA public key must be set");
    }

    // Verify that issuer public key exists in store
    if (!store.containsPublicKeyReference(issuerPublicKeyReference)) {
      throw new IllegalStateException(
          "Issuer public key reference not found in store: "
              + HexUtil.toHex(issuerPublicKeyReference));
    }

    // TODO: Get issuer certificate from store to retrieve issuer information (caAidSize,
    // caAidValue, caSerialNumber, caKeyId)
    // For now, set remaining fields with placeholders
    certificateBuilder
        .caAidSize((byte) 0)
        .caAidValue(new byte[16])
        .caSerialNumber(new byte[8])
        .caKeyId(new byte[4])
        .caRfu1(new byte[4])
        .caRfu2(new byte[2])
        .publicKeyHeader(new byte[34]);

    // TODO: Build certificate bytes, sign with signer, and set signature
    byte[] signature = new byte[256]; // Placeholder
    certificateBuilder.signature(signature);

    CaCertificate certificate = certificateBuilder.build();

    // TODO: Serialize certificate to 384-byte array
    throw new UnsupportedOperationException("Not yet implemented");
  }

  /**
   * Encodes a date in BCD format (YYYYMMDD).
   *
   * @param year The year (0-9999).
   * @param month The month (1-99).
   * @param day The day (1-99).
   * @return The encoded date (4 bytes).
   */
  private byte[] encodeDateBcd(int year, int month, int day) {
    byte[] date = new byte[4];
    date[0] = (byte) ((year / 1000) << 4 | (year / 100) % 10);
    date[1] = (byte) ((year / 10) % 10 << 4 | year % 10);
    date[2] = (byte) ((month / 10) << 4 | month % 10);
    date[3] = (byte) ((day / 10) << 4 | day % 10);
    return date;
  }
}
