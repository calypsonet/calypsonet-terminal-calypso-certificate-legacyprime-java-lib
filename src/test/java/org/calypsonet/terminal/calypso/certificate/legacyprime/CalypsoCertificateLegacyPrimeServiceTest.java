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

import org.junit.jupiter.api.Test;

class CalypsoCertificateLegacyPrimeServiceTest {

  @Test
  void getInstance_shouldReturnNonNullInstance() {
    // When
    CalypsoCertificateLegacyPrimeService service =
        CalypsoCertificateLegacyPrimeService.getInstance();

    // Then
    assertThat(service).isNotNull();
  }

  @Test
  void getInstance_shouldReturnSameInstanceOnMultipleCalls() {
    // When
    CalypsoCertificateLegacyPrimeService service1 =
        CalypsoCertificateLegacyPrimeService.getInstance();
    CalypsoCertificateLegacyPrimeService service2 =
        CalypsoCertificateLegacyPrimeService.getInstance();

    // Then
    assertThat(service1).isSameAs(service2);
  }

  @Test
  void getCalypsoCertificateLegacyPrimeApiFactory_shouldReturnNonNullFactory() {
    // Given
    CalypsoCertificateLegacyPrimeService service =
        CalypsoCertificateLegacyPrimeService.getInstance();

    // When
    CalypsoCertificateLegacyPrimeApiFactory factory =
        service.getCalypsoCertificateLegacyPrimeApiFactory();

    // Then
    assertThat(factory).isNotNull();
  }

  @Test
  void getCalypsoCertificateLegacyPrimeApiFactory_shouldReturnSameInstanceOnMultipleCalls() {
    // Given
    CalypsoCertificateLegacyPrimeService service =
        CalypsoCertificateLegacyPrimeService.getInstance();

    // When
    CalypsoCertificateLegacyPrimeApiFactory factory1 =
        service.getCalypsoCertificateLegacyPrimeApiFactory();
    CalypsoCertificateLegacyPrimeApiFactory factory2 =
        service.getCalypsoCertificateLegacyPrimeApiFactory();

    // Then
    assertThat(factory1).isSameAs(factory2);
  }

  @Test
  void integrationTest_serviceShouldProvideFullyFunctionalFactory() throws Exception {
    // Given
    CalypsoCertificateLegacyPrimeService service =
        CalypsoCertificateLegacyPrimeService.getInstance();
    CalypsoCertificateLegacyPrimeApiFactory factory =
        service.getCalypsoCertificateLegacyPrimeApiFactory();

    // When
    CalypsoCertificateLegacyPrimeStore store = factory.getCalypsoCertificateLegacyPrimeStore();

    // Then
    assertThat(store).isNotNull();
  }
}
