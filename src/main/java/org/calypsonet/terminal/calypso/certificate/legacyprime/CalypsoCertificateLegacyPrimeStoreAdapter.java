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
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.HexUtil;

/**
 * Adapter implementation of {@link CalypsoCertificateLegacyPrimeStore}.
 *
 * <p>This class manages the storage of Calypso Prime Legacy Certificate Authority (CA) certificates
 * and public keys, maintaining the chain of trust for certificate operations.
 *
 * @since 0.1.0
 */
final class CalypsoCertificateLegacyPrimeStoreAdapter
    implements CalypsoCertificateLegacyPrimeStore {

  private final Map<ByteArrayWrapper, RSAPublicKey> publicKeys;

  /**
   * Creates a new instance of the store.
   *
   * @since 0.1.0
   */
  CalypsoCertificateLegacyPrimeStoreAdapter() {
    this.publicKeys = new HashMap<>();
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public void addPcaPublicKey(byte[] pcaPublicKeyReference, RSAPublicKey pcaPublicKey) {
    Assert.getInstance()
        .notNull(pcaPublicKeyReference, "pcaPublicKeyReference")
        .notNull(pcaPublicKey, "pcaPublicKey")
        .isEqual(pcaPublicKey.getModulus().bitLength(), 2048, "PCA public key modulus bit length")
        .isEqual(pcaPublicKey.getPublicExponent().intValue(), 65537, "PCA public key exponent");

    ByteArrayWrapper keyRef = new ByteArrayWrapper(pcaPublicKeyReference);
    if (publicKeys.containsKey(keyRef)) {
      throw new IllegalStateException(
          "Public key reference already exists in the store: " + HexUtil.toHex(pcaPublicKeyReference));
    }

    publicKeys.put(keyRef, pcaPublicKey);
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public void addPcaPublicKey(byte[] pcaPublicKeyReference, byte[] pcaPublicKeyModulus) {
    Assert.getInstance()
        .notNull(pcaPublicKeyReference, "pcaPublicKeyReference")
        .notNull(pcaPublicKeyModulus, "pcaPublicKeyModulus")
        .isEqual(pcaPublicKeyModulus.length, 256, "pcaPublicKeyModulus length");

    ByteArrayWrapper keyRef = new ByteArrayWrapper(pcaPublicKeyReference);
    if (publicKeys.containsKey(keyRef)) {
      throw new IllegalStateException(
          "Public key reference already exists in the store: " + HexUtil.toHex(pcaPublicKeyReference));
    }

    // TODO: Create RSAPublicKey from modulus and add to store
    throw new UnsupportedOperationException("Not yet implemented");
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public byte[] addCalypsoCaCertificateLegacyPrime(byte[] caCertificate) {
    Assert.getInstance()
        .notNull(caCertificate, "caCertificate")
        .isEqual(caCertificate.length, 384, "caCertificate length");

    // TODO: Parse certificate, verify signature, extract public key reference and add to store
    throw new UnsupportedOperationException("Not yet implemented");
  }

  /**
   * Retrieves a public key by its reference.
   *
   * @param publicKeyReference The reference to the public key.
   * @return The RSA public key associated with the reference, or null if not found.
   * @since 0.1.0
   */
  RSAPublicKey getPublicKey(byte[] publicKeyReference) {
    return publicKeys.get(new ByteArrayWrapper(publicKeyReference));
  }

  /**
   * Checks if a public key reference exists in the store.
   *
   * @param publicKeyReference The reference to check.
   * @return true if the reference exists, false otherwise.
   * @since 0.1.0
   */
  boolean containsPublicKeyReference(byte[] publicKeyReference) {
    return publicKeys.containsKey(new ByteArrayWrapper(publicKeyReference));
  }

  /**
   * Wrapper class for byte arrays to enable their use as map keys.
   *
   * @since 0.1.0
   */
  private static final class ByteArrayWrapper {
    private final byte[] data;
    private final int hashCode;

    ByteArrayWrapper(byte[] data) {
      this.data = data.clone();
      this.hashCode = Arrays.hashCode(data);
    }

    @Override
    public boolean equals(Object obj) {
      if (this == obj) {
        return true;
      }
      if (obj == null || getClass() != obj.getClass()) {
        return false;
      }
      ByteArrayWrapper other = (ByteArrayWrapper) obj;
      return Arrays.equals(data, other.data);
    }

    @Override
    public int hashCode() {
      return hashCode;
    }

    byte[] getData() {
      return data.clone();
    }
  }
}
