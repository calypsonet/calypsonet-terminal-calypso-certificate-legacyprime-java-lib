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
 * Adapter implementation of {@link CalypsoCertificateLegacyPrimeApiFactory}.
 *
 * <p>This class provides factory methods for creating CA and card certificate generators.
 *
 * @since 0.1.0
 */
final class CalypsoCertificateLegacyPrimeApiFactoryAdapter
    implements CalypsoCertificateLegacyPrimeApiFactory {

  private final CalypsoCertificateLegacyPrimeStoreAdapter store;

  /**
   * Creates a new factory instance.
   *
   * @since 0.1.0
   */
  CalypsoCertificateLegacyPrimeApiFactoryAdapter() {
    this.store = new CalypsoCertificateLegacyPrimeStoreAdapter();
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CalypsoCertificateLegacyPrimeStore getCalypsoCertificateLegacyPrimeStore() {
    return store;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CalypsoCaCertificateLegacyPrimeGenerator createCalypsoCaCertificateLegacyPrimeGenerator(
      byte[] issuerPublicKeyReference, CalypsoCertificateLegacyPrimeSigner caCertificateSigner) {

    Assert.getInstance()
        .notNull(issuerPublicKeyReference, "issuerPublicKeyReference")
        .notNull(caCertificateSigner, "caCertificateSigner");

    // Check if issuer public key reference exists in store
    if (!store.containsPublicKeyReference(issuerPublicKeyReference)) {
      throw new IllegalStateException(
          "Issuer public key reference not found in store: "
              + HexUtil.toHex(issuerPublicKeyReference));
    }

    // Verify that the issuer certificate is valid for signing CA certificates
    // TODO: Add proper certificate validation logic

    return new CalypsoCaCertificateLegacyPrimeGeneratorAdapter(
        store, issuerPublicKeyReference, caCertificateSigner);
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CalypsoCardCertificateLegacyPrimeGenerator
      createCalypsoCardCertificateLegacyPrimeGenerator(
          byte[] issuerPublicKeyReference,
          CalypsoCertificateLegacyPrimeSigner cardCertificateSigner) {

    Assert.getInstance()
        .notNull(issuerPublicKeyReference, "issuerPublicKeyReference")
        .notNull(cardCertificateSigner, "cardCertificateSigner");

    // Check if issuer public key reference exists in store
    if (!store.containsPublicKeyReference(issuerPublicKeyReference)) {
      throw new IllegalStateException(
          "Issuer public key reference not found in store: "
              + HexUtil.toHex(issuerPublicKeyReference));
    }

    // Verify that the issuer certificate is valid for signing card certificates
    // TODO: Add proper certificate validation logic

    return new CalypsoCardCertificateLegacyPrimeGeneratorAdapter(
        store, issuerPublicKeyReference, cardCertificateSigner);
  }
}
