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

import calypso.certificate.legacyprime.CalypsoCaCertificateLegacyPrimeGenerator;
import calypso.certificate.legacyprime.CalypsoCardCertificateLegacyPrimeGenerator;
import calypso.certificate.legacyprime.CalypsoCertificateLegacyPrimeApiFactory;
import calypso.certificate.legacyprime.CalypsoCertificateLegacyPrimeStore;
import calypso.certificate.legacyprime.spi.CalypsoCertificateLegacyPrimeSigner;

/**
 * Adapter implementation of {@link CalypsoCertificateLegacyPrimeApiFactory}.
 *
 * <p>This class provides the implementation for creating Calypso Prime Legacy certificate builders
 * and managing the certificate store.
 *
 * @since 0.1.0
 */
public final class CalypsoCertificateLegacyPrimeApiFactoryAdapter
    implements CalypsoCertificateLegacyPrimeApiFactory {

  private static final CalypsoCertificateLegacyPrimeApiFactoryAdapter INSTANCE =
      new CalypsoCertificateLegacyPrimeApiFactoryAdapter();

  /** Private constructor for singleton pattern. */
  private CalypsoCertificateLegacyPrimeApiFactoryAdapter() {}

  /**
   * Returns the unique instance of this factory.
   *
   * @return A non-null reference.
   * @since 0.1.0
   */
  public static CalypsoCertificateLegacyPrimeApiFactoryAdapter getInstance() {
    return INSTANCE;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CalypsoCertificateLegacyPrimeStore getCalypsoCertificateLegacyPrimeStore() {
    // TODO: Implement certificate store
    throw new UnsupportedOperationException("Not yet implemented");
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CalypsoCaCertificateLegacyPrimeGenerator createCalypsoCaCertificateLegacyPrimeGenerator(
      byte[] issuerPublicKeyReference, CalypsoCertificateLegacyPrimeSigner caCertificateSigner) {
    // TODO: Implement CA certificate generator
    throw new UnsupportedOperationException("Not yet implemented");
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
    // TODO: Implement card certificate generator
    throw new UnsupportedOperationException("Not yet implemented");
  }
}
