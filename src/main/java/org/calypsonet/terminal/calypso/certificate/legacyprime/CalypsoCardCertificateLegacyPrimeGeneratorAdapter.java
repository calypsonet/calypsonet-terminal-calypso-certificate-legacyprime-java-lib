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

  private byte[] cardPublicKey;
  private Integer startYear;
  private Integer startMonth;
  private Integer startDay;
  private Integer endYear;
  private Integer endMonth;
  private Integer endDay;
  private byte[] cardAid;
  private byte[] cardSerialNumber;
  private byte[] cardStartupInfo;
  private int index;

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
    this.index = 0; // Default value
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

    this.cardPublicKey = cardPublicKey.clone();
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

    this.startYear = year;
    this.startMonth = month;
    this.startDay = day;
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

    this.endYear = year;
    this.endMonth = month;
    this.endDay = day;
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

    this.cardAid = aid.clone();
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

    this.cardSerialNumber = serialNumber.clone();
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

    this.cardStartupInfo = startupInfo.clone();
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CalypsoCardCertificateLegacyPrimeGenerator withIndex(int index) {
    this.index = index;
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
    if (cardPublicKey == null) {
      throw new IllegalStateException("Card public key must be set");
    }
    if (cardAid == null) {
      throw new IllegalStateException("Card AID must be set");
    }
    if (cardSerialNumber == null) {
      throw new IllegalStateException("Card serial number must be set");
    }
    if (cardStartupInfo == null) {
      throw new IllegalStateException("Card startup info must be set");
    }

    // Verify that issuer public key exists in store
    if (!store.containsPublicKeyReference(issuerPublicKeyReference)) {
      throw new IllegalStateException(
          "Issuer public key reference not found in store: "
              + HexUtil.toHex(issuerPublicKeyReference));
    }

    // TODO: Build certificate data structure
    // TODO: Create recoverable data
    // TODO: Sign certificate using the signer
    // TODO: Return 316-byte certificate

    throw new UnsupportedOperationException("Not yet implemented");
  }
}
