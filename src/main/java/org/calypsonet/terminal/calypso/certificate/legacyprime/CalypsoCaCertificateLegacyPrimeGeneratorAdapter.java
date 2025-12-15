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

    certificateBuilder.startDate(CertificateUtils.encodeDateBcd(year, month, day));
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

    certificateBuilder.endDate(CertificateUtils.encodeDateBcd(year, month, day));
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

    // Extract CA information from caPublicKeyReference (29 bytes)
    // Structure: caAidSize (1) + caAidValue (16) + caSerialNumber (8) + caKeyId (4)
    byte caAidSize = caPublicKeyReference[0];
    byte[] caAidValue = new byte[16];
    System.arraycopy(caPublicKeyReference, 1, caAidValue, 0, 16);
    byte[] caSerialNumber = new byte[8];
    System.arraycopy(caPublicKeyReference, 17, caSerialNumber, 0, 8);
    byte[] caKeyId = new byte[4];
    System.arraycopy(caPublicKeyReference, 25, caKeyId, 0, 4);

    // Build the certificate with extracted information
    certificateBuilder
        .caAidSize(caAidSize)
        .caAidValue(caAidValue)
        .caSerialNumber(caSerialNumber)
        .caKeyId(caKeyId)
        .caRfu1(new byte[4])
        .caRfu2(new byte[2]);

    // Extract public key header (first 34 bytes of RSA modulus)
    CaCertificate tempCert = certificateBuilder.build();
    RSAPublicKey rsaPublicKey = tempCert.getRsaPublicKey();
    if (rsaPublicKey == null) {
      throw new IllegalStateException("CA public key not set");
    }

    byte[] modulus = rsaPublicKey.getModulus().toByteArray();
    byte[] publicKeyHeader = new byte[34];

    // Handle potential leading zero byte in modulus
    int srcPos = (modulus.length == 257 && modulus[0] == 0) ? 1 : 0;
    System.arraycopy(modulus, srcPos, publicKeyHeader, 0, 34);

    certificateBuilder.publicKeyHeader(publicKeyHeader);

    // Build certificate bytes for signing (128 bytes from KCertType to KCertPublicKeyHeader)
    byte[] dataToSign = buildCertificateDataForSigning();

    // Sign the data using the signer (no recoverable data for CA certificates)
    byte[] signedCertificate = signer.generateSignedCertificate(dataToSign, new byte[0]);

    // Extract signature from signed certificate (last 256 bytes)
    if (signedCertificate.length != dataToSign.length + 256) {
      throw new IllegalStateException(
          "Signed certificate must be "
              + (dataToSign.length + 256)
              + " bytes, got "
              + signedCertificate.length
              + " bytes");
    }

    byte[] signature = new byte[256];
    System.arraycopy(signedCertificate, dataToSign.length, signature, 0, 256);

    certificateBuilder.signature(signature);

    // Build the final certificate
    CaCertificate certificate = certificateBuilder.build();

    // Serialize certificate to 384-byte array
    return serializeCaCertificate(certificate);
  }

  /**
   * Builds the certificate data to be signed (128 bytes).
   *
   * @return The data to sign.
   */
  private byte[] buildCertificateDataForSigning() {
    CaCertificate tempCert = certificateBuilder.build();
    return tempCert.toBytesForSigning();
  }

  /**
   * Serializes the CA certificate to a 384-byte array.
   *
   * @param certificate The certificate to serialize.
   * @return The serialized certificate.
   */
  private byte[] serializeCaCertificate(CaCertificate certificate) {
    return certificate.toBytes();
  }
}
