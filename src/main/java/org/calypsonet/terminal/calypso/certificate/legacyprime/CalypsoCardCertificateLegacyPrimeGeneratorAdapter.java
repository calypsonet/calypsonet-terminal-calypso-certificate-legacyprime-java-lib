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

import org.calypsonet.terminal.calypso.certificate.legacyprime.spi.CalypsoCertificateLegacyPrimeSigner;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.HexUtil;

/**
 * Adapter implementation of {@link CalypsoCardCertificateLegacyPrimeGenerator}.
 *
 * <p>This class provides a builder pattern for creating Calypso Prime Legacy card certificates with
 * configurable parameters.
 *
 * @since 0.1.0
 */
final class CalypsoCardCertificateLegacyPrimeGeneratorAdapter
    implements CalypsoCardCertificateLegacyPrimeGenerator {

  private final CalypsoCertificateLegacyPrimeStoreAdapter store;
  private final byte[] issuerPublicKeyReference;
  private final CalypsoCertificateLegacyPrimeSigner signer;
  private final CardCertificate.Builder certificateBuilder;

  /**
   * Creates a new generator instance.
   *
   * @param store The store containing the issuer certificates.
   * @param issuerPublicKeyReference The reference to the issuer's public key.
   * @param signer The signer to use for certificate signing.
   * @since 0.1.0
   */
  CalypsoCardCertificateLegacyPrimeGeneratorAdapter(
      CalypsoCertificateLegacyPrimeStoreAdapter store,
      byte[] issuerPublicKeyReference,
      CalypsoCertificateLegacyPrimeSigner signer) {
    this.store = store;
    this.issuerPublicKeyReference = issuerPublicKeyReference.clone();
    this.signer = signer;
    // Initialize the certificate builder with known values
    this.certificateBuilder =
        CardCertificate.builder()
            .certType((byte) 0x91)
            .structureVersion((byte) 0x01)
            .issuerKeyReference(issuerPublicKeyReference)
            .cardIndex(new byte[4]); // Default index = 0
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CalypsoCardCertificateLegacyPrimeGenerator withCardPublicKey(byte[] cardPublicKey) {
    Assert.getInstance().notNull(cardPublicKey, "cardPublicKey");
    Assert.getInstance().isEqual(cardPublicKey.length, 64, "cardPublicKey length");

    certificateBuilder.eccPublicKey(cardPublicKey);
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CalypsoCardCertificateLegacyPrimeGenerator withStartDate(int year, int month, int day) {
    Assert.getInstance().isInRange(year, 0, 9999, "year");
    Assert.getInstance().isInRange(month, 1, 99, "month");
    Assert.getInstance().isInRange(day, 1, 99, "day");

    certificateBuilder.startDate(encodeDateBcd(year, month, day));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CalypsoCardCertificateLegacyPrimeGenerator withEndDate(int year, int month, int day) {
    Assert.getInstance().isInRange(year, 0, 9999, "year");
    Assert.getInstance().isInRange(month, 1, 99, "month");
    Assert.getInstance().isInRange(day, 1, 99, "day");

    certificateBuilder.endDate(encodeDateBcd(year, month, day));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CalypsoCardCertificateLegacyPrimeGenerator withCardAid(byte[] aid) {
    Assert.getInstance().notNull(aid, "aid");
    Assert.getInstance().isInRange(aid.length, 5, 16, "aid length");

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
    byte cardAidSize = (byte) aid.length;
    byte[] cardAidValue = new byte[16];
    System.arraycopy(aid, 0, cardAidValue, 0, aid.length);

    certificateBuilder.cardAidSize(cardAidSize).cardAidValue(cardAidValue);
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CalypsoCardCertificateLegacyPrimeGenerator withCardSerialNumber(byte[] serialNumber) {
    Assert.getInstance().notNull(serialNumber, "serialNumber");
    Assert.getInstance().isEqual(serialNumber.length, 8, "serialNumber length");

    certificateBuilder.cardSerialNumber(serialNumber);
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CalypsoCardCertificateLegacyPrimeGenerator withCardStartupInfo(byte[] startupInfo) {
    Assert.getInstance().notNull(startupInfo, "startupInfo");
    Assert.getInstance().isEqual(startupInfo.length, 7, "startupInfo length");

    certificateBuilder.cardInfo(startupInfo);
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CalypsoCardCertificateLegacyPrimeGenerator withIndex(int index) {
    // Encode index as 4-byte big-endian
    byte[] cardIndex = new byte[4];
    cardIndex[0] = (byte) (index >> 24);
    cardIndex[1] = (byte) (index >> 16);
    cardIndex[2] = (byte) (index >> 8);
    cardIndex[3] = (byte) index;

    certificateBuilder.cardIndex(cardIndex);
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public byte[] generate() {
    // Verify that issuer public key exists in store
    if (!store.containsPublicKeyReference(issuerPublicKeyReference)) {
      throw new IllegalStateException(
          "Issuer public key reference not found in store: "
              + HexUtil.toHex(issuerPublicKeyReference));
    }

    // TODO: Get issuer certificate from store to retrieve issuer information (issuerAidSize,
    // issuerAidValue, issuerSerialNumber, issuerKeyId)
    // For now, set remaining fields with placeholders
    certificateBuilder
        .issuerAidSize((byte) 0)
        .issuerAidValue(new byte[16])
        .issuerSerialNumber(new byte[8])
        .issuerKeyId(new byte[4])
        .cardRights((byte) 0)
        .cardRfu(new byte[18])
        .eccRfu(new byte[124]);

    // TODO: Build certificate bytes, create recoverable data, sign with signer in ISO9796-2
    // recoverable mode
    byte[] signature = new byte[256]; // Placeholder
    certificateBuilder.signature(signature);

    CardCertificate certificate = certificateBuilder.build();

    // TODO: Serialize certificate to 316-byte array
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
