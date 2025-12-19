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
    CaCertificate issuerCaCert = store.getCaCertificate(issuerPublicKeyReference);
    if (issuerCaCert != null) {
      // Check CA rights for CA certificate signing
      CaRights caRights = issuerCaCert.getCaRights();
      CertRight caCertRight = caRights.getCaCertRight();

      if (caCertRight == CertRight.SHALL_NOT_SIGN) {
        throw new IllegalStateException(
            "Issuer CA certificate does not have the right to sign CA certificates.");
      }
    }
    // If issuerCaCert is null, it means we're using a PCA public key, which is allowed

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
    CaCertificate issuerCert = store.getCaCertificate(issuerPublicKeyReference);
    if (issuerCert != null) {
      // Check CA rights for card certificate signing
      CaRights caRights = issuerCert.getCaRights();
      CertRight cardCertRight = caRights.getCardCertRight();

      if (cardCertRight == CertRight.SHALL_NOT_SIGN) {
        throw new IllegalStateException(
            "Issuer certificate does not have the right to sign card certificates");
      }
    }
    // If issuerCert is null, it means we're using a PCA public key, which is allowed

    return new CalypsoCardCertificateLegacyPrimeGeneratorAdapter(
        store, issuerPublicKeyReference, cardCertificateSigner);
  }
}
