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

/**
 * Main service for accessing the Calypso Certificate Legacy Prime API.
 *
 * <p>This class provides a singleton instance to access the API factory for creating certificate
 * generators and accessing the certificate store.
 *
 * @since 0.1.0
 */
public final class CalypsoCertificateLegacyPrimeService {

  private static final CalypsoCertificateLegacyPrimeService INSTANCE =
      new CalypsoCertificateLegacyPrimeService();

  private final CalypsoCertificateLegacyPrimeApiFactory apiFactory;

  /**
   * Private constructor to enforce singleton pattern.
   *
   * @since 0.1.0
   */
  private CalypsoCertificateLegacyPrimeService() {
    this.apiFactory = new CalypsoCertificateLegacyPrimeApiFactoryAdapter();
  }

  /**
   * Returns the singleton instance of the service.
   *
   * @return A non-null reference to the service instance.
   * @since 0.1.0
   */
  public static CalypsoCertificateLegacyPrimeService getInstance() {
    return INSTANCE;
  }

  /**
   * Returns the API factory for creating CA and card certificate generators.
   *
   * <p>The factory provides access to the certificate store and methods to create certificate
   * generators with external signers.
   *
   * @return A non-null reference to the API factory.
   * @since 0.1.0
   */
  public CalypsoCertificateLegacyPrimeApiFactory getCalypsoCertificateLegacyPrimeApiFactory() {
    return apiFactory;
  }
}
