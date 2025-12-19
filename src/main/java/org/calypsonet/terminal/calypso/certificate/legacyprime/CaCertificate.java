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

import static org.calypsonet.terminal.calypso.certificate.legacyprime.CertificateConstants.RSA_MODULUS_SIZE;
import static org.calypsonet.terminal.calypso.certificate.legacyprime.CertificateConstants.RSA_SIGNATURE_SIZE;

import java.security.interfaces.RSAPublicKey;
import java.time.LocalDate;
import java.util.Arrays;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.ISO9796d2PSSSigner;
import org.eclipse.keyple.core.util.Assert;

/**
 * Internal class representing a CA Certificate with all its fields.
 *
 * <p>This class stores all fields from a 384-byte CA certificate according to the Calypso Prime
 * Legacy specification.
 *
 * @since 0.1.0
 */
final class CaCertificate {
  private final CertificateType certType;
  private final byte structureVersion;
  private final KeyReference issuerKeyReference;
  private final KeyReference caTargetKeyReference;
  private final LocalDate startDate;
  private final byte[] caRfu1;
  private final CaRights caRights;
  private final CaScope caScope;
  private final LocalDate endDate;
  private final Aid caTargetAid;
  private final OperatingMode caOperatingMode;
  private final byte[] caRfu2;
  private final byte[] publicKeyHeader;
  private final byte[] signature;
  private final RSAPublicKey rsaPublicKey;

  /**
   * Creates a new CA certificate instance.
   *
   * @param builder The builder containing all certificate fields.
   * @since 0.1.0
   */
  private CaCertificate(Builder builder) {
    this.certType = builder.certType;
    this.structureVersion = builder.structureVersion;
    this.issuerKeyReference = builder.issuerKeyReference;
    this.caTargetKeyReference = builder.caTargetKeyReference;
    this.startDate = builder.startDate;
    this.caRfu1 = builder.caRfu1;
    this.caRights = builder.caRights;
    this.caScope = builder.caScope;
    this.endDate = builder.endDate;
    this.caTargetAid = builder.caTargetAid;
    this.caOperatingMode = builder.caOperatingMode;
    this.caRfu2 = builder.caRfu2;
    this.publicKeyHeader = builder.publicKeyHeader;
    this.signature = builder.signature;
    this.rsaPublicKey = builder.rsaPublicKey;
  }

  /**
   * Verifies a CA certificate signature and recovers the CA's RSA public key using ISO/IEC 9796-2
   * message recovery.
   *
   * <p>This method performs two operations:
   *
   * <ol>
   *   <li>Verifies the CA certificate signature using the issuer's RSA public key
   *   <li>Recovers the CA's RSA modulus by combining the 34-byte public key header (transmitted in
   *       clear) with the 222 bytes of modulus data recovered from the signature block
   * </ol>
   *
   * <p>The signature verification and message recovery follow the ISO/IEC 9796-2 PSS (Probabilistic
   * Signature Scheme) standard with SHA-256 digest.
   *
   * @param caCertificate The complete CA certificate (290 bytes).
   * @param caPublicKeyHeader The first 34 bytes of the CA's RSA modulus, transmitted in clear.
   * @param issuerPublicKey The RSA public key (2048-bit) of the certificate issuer, used to verify
   *     the signature and recover the remaining modulus bytes.
   * @return A non-null 2048-bit RSA public key with exponent 65537, reconstructed from the header
   *     and recovered data.
   * @throws IllegalArgumentException if any parameter is null, has invalid length, or if the
   *     issuerPublicKey is not a valid 2048-bit RSA key.
   * @throws CertificateConsistencyException if signature verification fails or message recovery
   *     encounters an error.
   * @since 0.1.0
   */
  private static RSAPublicKey checkCaCertificateSignatureAndRecoverRsaPublicKey(
      byte[] caCertificate, byte[] caPublicKeyHeader, RSAPublicKey issuerPublicKey) {
    Assert.getInstance()
        .notNull(caCertificate, "caCertificate")
        .isEqual(
            caCertificate.length, CertificateConstants.CA_CERTIFICATE_SIZE, "caCertificate.length")
        .notNull(caPublicKeyHeader, "caPublicKeyHeader")
        .isEqual(
            caPublicKeyHeader.length,
            CertificateConstants.PUBLIC_KEY_HEADER_SIZE,
            "caPublicKeyHeader.length");
    CertificateUtils.checkRSA2048PublicKey(issuerPublicKey);

    // check signature and recover data according to ISO/IEC 9796-2
    byte[] recoveredData =
        checkCaCertificateSignatureAndRecoverData(caCertificate, issuerPublicKey);

    // Combines the recovered data and the header transmitted in clear to create the CA public key
    byte[] caPublicKeyModulus = new byte[RSA_MODULUS_SIZE];
    System.arraycopy(caPublicKeyHeader, 0, caPublicKeyModulus, 0, caPublicKeyHeader.length);
    System.arraycopy(
        recoveredData, 0, caPublicKeyModulus, caPublicKeyHeader.length, recoveredData.length);
    return CertificateUtils.generateRSAPublicKeyFromModulus(caPublicKeyModulus);
  }

  /**
   * Verifies a CA certificate signature and recovers embedded data using ISO/IEC 9796-2 message
   * recovery with PSS.
   *
   * <p>This method implements the ISO/IEC 9796-2 signature scheme with message recovery:
   *
   * <ol>
   *   <li>Extracts the 256-byte signature block from the end of the certificate
   *   <li>Performs PSS signature verification with SHA-256 digest and message recovery
   *   <li>Updates the signer with the certificate data (excluding the signature)
   *   <li>Verifies the signature validity
   * </ol>
   *
   * <p>The recovered message contains 222 bytes of the CA's RSA modulus that were embedded in the
   * signature during signing.
   *
   * @param certificate The complete CA certificate containing data and signature.
   * @param issuerPublicKey The issuer's RSA public key used for signature verification.
   * @return A 222-byte array containing the recovered modulus data.
   * @throws CertificateConsistencyException if signature verification fails or if an error occurs
   *     during message recovery.
   */
  private static byte[] checkCaCertificateSignatureAndRecoverData(
      byte[] certificate, RSAPublicKey issuerPublicKey) throws CertificateConsistencyException {
    RSAKeyParameters pubParams =
        new RSAKeyParameters(
            false, issuerPublicKey.getModulus(), issuerPublicKey.getPublicExponent());

    ISO9796d2PSSSigner pssSign =
        new ISO9796d2PSSSigner(new RSAEngine(), new SHA256Digest(), 0, true);

    pssSign.init(false, pubParams);

    try {
      pssSign.updateWithRecoveredMessage(
          Arrays.copyOfRange(
              certificate, certificate.length - RSA_SIGNATURE_SIZE, certificate.length));

      pssSign.update(certificate, 0, certificate.length - RSA_SIGNATURE_SIZE);

      byte[] signature =
          Arrays.copyOfRange(
              certificate, certificate.length - RSA_SIGNATURE_SIZE, certificate.length);
      if (!pssSign.verifySignature(signature)) {
        throw new CertificateConsistencyException("Challenge PSS certificate verification failed");
      }

      return pssSign.getRecoveredMessage();
    } catch (InvalidCipherTextException e) {
      throw new CertificateConsistencyException(e.getMessage(), e);
    } catch (RuntimeException e) {
      throw new CertificateConsistencyException(
          "Certificate signature verification failed: " + e.getMessage(), e);
    }
  }

  /**
   * Retrieves the certificate type associated with this CA certificate.
   *
   * @return The certificate type as a {@code CertificateType} enum value.
   * @since 0.1.0
   */
  CertificateType getCertType() {
    return certType;
  }

  /**
   * Gets the structure version.
   *
   * @return The structure version (0x01).
   * @since 0.1.0
   */
  byte getStructureVersion() {
    return structureVersion;
  }

  /**
   * Gets the issuer key reference.
   *
   * @return A copy of the issuer key reference (29 bytes).
   * @since 0.1.0
   */
  byte[] getIssuerKeyReference() {
    return issuerKeyReference.toBytes();
  }

  /**
   * Gets the CA target key reference.
   *
   * @return A copy of the CA target key reference (29 bytes).
   * @since 0.1.0
   */
  byte[] getCaTargetKeyReference() {
    return caTargetKeyReference.toBytes();
  }

  /**
   * Gets the start date.
   *
   * @return The start date as a LocalDate, or null if not set.
   * @since 0.1.0
   */
  LocalDate getStartDate() {
    return startDate;
  }

  /**
   * Gets the RFU field 1.
   *
   * @return A copy of the RFU field 1 (4 bytes).
   * @since 0.1.0
   */
  byte[] getCaRfu1() {
    return caRfu1.clone();
  }

  /**
   * Retrieves the CA rights associated with this certificate.
   *
   * @return The CA rights object representing permissions and capabilities related to card and CA
   *     certificate signing.
   * @since 0.1.0
   */
  CaRights getCaRights() {
    return caRights;
  }

  /**
   * Retrieves the CA scope associated with this certificate.
   *
   * @return The CA scope as a {@code CaScope} enum value.
   * @since 0.1.0
   */
  CaScope getCaScope() {
    return caScope;
  }

  /**
   * Gets the end date.
   *
   * @return The end date as a LocalDate, or null if not set.
   * @since 0.1.0
   */
  LocalDate getEndDate() {
    return endDate;
  }

  /**
   * Gets the target AID object.
   *
   * @return The target AID, or null if not set (RFU).
   * @since 0.1.0
   */
  Aid getCaTargetAid() {
    return caTargetAid;
  }

  /**
   * Gets the CA operating mode.
   *
   * @return The CA operating mode indicating whether truncation is allowed or forbidden.
   * @since 0.1.0
   */
  OperatingMode getCaOperatingMode() {
    return caOperatingMode;
  }

  /**
   * Gets the RFU field 2.
   *
   * @return A copy of the RFU field 2 (2 bytes).
   * @since 0.1.0
   */
  byte[] getCaRfu2() {
    return caRfu2.clone();
  }

  /**
   * Gets the public key header.
   *
   * @return A copy of the public key header (34 bytes).
   * @since 0.1.0
   */
  byte[] getPublicKeyHeader() {
    return publicKeyHeader.clone();
  }

  /**
   * Gets the signature.
   *
   * @return A copy of the signature (256 bytes).
   * @since 0.1.0
   */
  byte[] getSignature() {
    return signature.clone();
  }

  /**
   * Gets the RSA public key.
   *
   * <p>The RSA public key is reconstructed from the certificate data during parsing.
   *
   * @return The RSA public key, or null if not set.
   * @since 0.1.0
   */
  RSAPublicKey getRsaPublicKey() {
    return rsaPublicKey;
  }

  /**
   * Serializes the certificate fields to bytes (without signature).
   *
   * <p>This represents the data that must be signed according to the Calypso Prime Legacy
   * specification (128 bytes from KCertType to KCertPublicKeyHeader).
   *
   * @return A 128-byte array containing the certificate data to be signed.
   * @since 0.1.0
   */
  byte[] toBytesForSigning() {
    byte[] data = new byte[CertificateConstants.CA_DATA_FOR_SIGNING_SIZE];
    int offset = 0;

    // KCertType (1 byte)
    data[offset++] = certType.getValue();

    // KCertStructureVersion (1 byte)
    data[offset++] = structureVersion;

    // KCertIssuerKeyReference (29 bytes)
    byte[] issuerKeyRefBytes = issuerKeyReference.toBytes();
    System.arraycopy(issuerKeyRefBytes, 0, data, offset, CertificateConstants.KEY_REFERENCE_SIZE);
    offset += CertificateConstants.KEY_REFERENCE_SIZE;

    // KCertCaTargetKeyReference (29 bytes)
    byte[] caTargetKeyRefBytes = caTargetKeyReference.toBytes();
    System.arraycopy(caTargetKeyRefBytes, 0, data, offset, CertificateConstants.KEY_REFERENCE_SIZE);
    offset += CertificateConstants.KEY_REFERENCE_SIZE;

    // KCertStartDate (4 bytes)
    byte[] encodedStartDate =
        CertificateUtils.encodeDateBcd(
            startDate.getYear(), startDate.getMonthValue(), startDate.getDayOfMonth());
    System.arraycopy(encodedStartDate, 0, data, offset, CertificateConstants.DATE_SIZE);
    offset += CertificateConstants.DATE_SIZE;

    // KCertCaRfu1 (4 bytes)
    System.arraycopy(caRfu1, 0, data, offset, CertificateConstants.CA_RFU1_SIZE);
    offset += CertificateConstants.CA_RFU1_SIZE;

    // KCertCaRights (1 byte)
    data[offset++] = caRights.toByte();

    // KCertCaScope (1 byte)
    data[offset++] = caScope.getValue();

    // KCertEndDate (4 bytes)
    byte[] encodedEndDate =
        CertificateUtils.encodeDateBcd(
            endDate.getYear(), endDate.getMonthValue(), endDate.getDayOfMonth());
    System.arraycopy(encodedEndDate, 0, data, offset, CertificateConstants.DATE_SIZE);
    offset += CertificateConstants.DATE_SIZE;

    // AID (17 bytes: 1 byte size + 16 bytes value)
    byte[] aidBytes = caTargetAid.toBytes();
    System.arraycopy(aidBytes, 0, data, offset, 1 + CertificateConstants.AID_VALUE_SIZE);
    offset += 1 + CertificateConstants.AID_VALUE_SIZE;

    // KCertCaOperatingMode (1 byte)
    data[offset++] = caOperatingMode.getValue();

    // KCertCaRfu2 (2 bytes)
    System.arraycopy(caRfu2, 0, data, offset, CertificateConstants.CA_RFU2_SIZE);
    offset += CertificateConstants.CA_RFU2_SIZE;

    // KCertPublicKeyHeader (34 bytes)
    System.arraycopy(publicKeyHeader, 0, data, offset, CertificateConstants.PUBLIC_KEY_HEADER_SIZE);

    return data;
  }

  /**
   * Serializes the complete certificate to bytes (with signature).
   *
   * <p>This represents the full 384-byte CA certificate according to the Calypso Prime Legacy
   * specification.
   *
   * @return A 384-byte array containing the complete certificate.
   * @since 0.1.0
   */
  byte[] toBytes() {
    byte[] serialized = new byte[CertificateConstants.CA_CERTIFICATE_SIZE];
    int offset = 0;

    // Copy the data to be signed (128 bytes)
    byte[] dataForSigning = toBytesForSigning();
    System.arraycopy(
        dataForSigning, 0, serialized, offset, CertificateConstants.CA_DATA_FOR_SIGNING_SIZE);
    offset += CertificateConstants.CA_DATA_FOR_SIGNING_SIZE;

    // KCertSignature (256 bytes)
    System.arraycopy(signature, 0, serialized, offset, CertificateConstants.RSA_SIGNATURE_SIZE);

    return serialized;
  }

  /**
   * Parses a CA certificate from its byte array representation.
   *
   * <p>This method deserializes a 384-byte CA certificate according to the Calypso Prime Legacy
   * specification and reconstructs all certificate fields including the RSA public key.
   *
   * @param caCertificate The 384-byte certificate to parse.
   * @return The parsed CA certificate.
   * @throws CertificateConsistencyException If the certificate has an unexpected format or has an
   *     incorrect signature.
   * @since 0.1.0
   */
  static CaCertificate fromBytes(byte[] caCertificate, RSAPublicKey issuerPublicKey) {

    int offset = 0;

    // KCertType (1 byte)
    byte certType = caCertificate[offset++];

    // KCertStructureVersion (1 byte)
    byte structureVersion = caCertificate[offset++];

    // KCertIssuerKeyReference (29 bytes)
    byte[] issuerKeyReference = new byte[CertificateConstants.KEY_REFERENCE_SIZE];
    System.arraycopy(
        caCertificate, offset, issuerKeyReference, 0, CertificateConstants.KEY_REFERENCE_SIZE);
    offset += CertificateConstants.KEY_REFERENCE_SIZE;

    // KCertCaTargetKeyReference (29 bytes)
    byte[] caTargetKeyReference = new byte[CertificateConstants.KEY_REFERENCE_SIZE];
    System.arraycopy(
        caCertificate, offset, caTargetKeyReference, 0, CertificateConstants.KEY_REFERENCE_SIZE);
    offset += CertificateConstants.KEY_REFERENCE_SIZE;

    // KCertStartDate (4 bytes)
    byte[] startDate = new byte[CertificateConstants.DATE_SIZE];
    System.arraycopy(caCertificate, offset, startDate, 0, CertificateConstants.DATE_SIZE);
    offset += CertificateConstants.DATE_SIZE;

    // KCertCaRfu1 (4 bytes)
    byte[] caRfu1 = new byte[CertificateConstants.CA_RFU1_SIZE];
    System.arraycopy(caCertificate, offset, caRfu1, 0, CertificateConstants.CA_RFU1_SIZE);
    offset += CertificateConstants.CA_RFU1_SIZE;

    // KCertCaRights (1 byte)
    byte caRights = caCertificate[offset++];

    // KCertCaScope (1 byte)
    byte caScope = caCertificate[offset++];

    // KCertEndDate (4 bytes)
    byte[] endDate = new byte[CertificateConstants.DATE_SIZE];
    System.arraycopy(caCertificate, offset, endDate, 0, CertificateConstants.DATE_SIZE);
    offset += CertificateConstants.DATE_SIZE;

    // KCertCaTargetAidSize (1 byte)
    byte caTargetAidSize = caCertificate[offset++];

    // KCertCaTargetAidValue (16 bytes)
    byte[] caTargetAidValue = new byte[CertificateConstants.AID_VALUE_SIZE];
    System.arraycopy(
        caCertificate, offset, caTargetAidValue, 0, CertificateConstants.AID_VALUE_SIZE);
    offset += CertificateConstants.AID_VALUE_SIZE;

    // KCertCaOperatingMode (1 byte)
    byte caOperatingMode = caCertificate[offset++];

    // KCertCaRfu2 (2 bytes)
    byte[] caRfu2 = new byte[CertificateConstants.CA_RFU2_SIZE];
    System.arraycopy(caCertificate, offset, caRfu2, 0, CertificateConstants.CA_RFU2_SIZE);
    offset += CertificateConstants.CA_RFU2_SIZE;

    // KCertPublicKeyHeader (34 bytes)
    byte[] caPublicKeyHeader = new byte[CertificateConstants.PUBLIC_KEY_HEADER_SIZE];
    System.arraycopy(
        caCertificate, offset, caPublicKeyHeader, 0, CertificateConstants.PUBLIC_KEY_HEADER_SIZE);
    offset += CertificateConstants.PUBLIC_KEY_HEADER_SIZE;

    // KCertSignature (256 bytes)
    byte[] signature = new byte[CertificateConstants.RSA_SIGNATURE_SIZE];
    System.arraycopy(caCertificate, offset, signature, 0, CertificateConstants.RSA_SIGNATURE_SIZE);

    try {
      // Reconstruct the RSA public key from the public key header and signature
      RSAPublicKey rsaPublicKey =
          checkCaCertificateSignatureAndRecoverRsaPublicKey(
              caCertificate, caPublicKeyHeader, issuerPublicKey);

      return CaCertificate.builder()
          .certType(certType)
          .structureVersion(structureVersion)
          .issuerKeyReference(issuerKeyReference)
          .caTargetKeyReference(caTargetKeyReference)
          .startDate(startDate)
          .caRfu1(caRfu1)
          .caRights(caRights)
          .caScope(caScope)
          .endDate(endDate)
          .caTargetAid(caTargetAidSize, caTargetAidValue)
          .caOperatingMode(caOperatingMode)
          .caRfu2(caRfu2)
          .publicKeyHeader(caPublicKeyHeader)
          .signature(signature)
          .rsaPublicKey(rsaPublicKey)
          .build();
    } catch (IllegalArgumentException e) {
      throw new CertificateConsistencyException(e.getMessage(), e);
    }
  }

  /**
   * Creates a new builder instance.
   *
   * @return A new builder.
   * @since 0.1.0
   */
  static Builder builder() {
    return new Builder();
  }

  /**
   * Builder for {@link CaCertificate}.
   *
   * @since 0.1.0
   */
  static final class Builder {
    private CertificateType certType;
    private byte structureVersion;
    private KeyReference issuerKeyReference;
    private KeyReference caTargetKeyReference;
    private LocalDate startDate;
    private byte[] caRfu1;
    private CaRights caRights;
    private CaScope caScope;
    private LocalDate endDate;
    private Aid caTargetAid;
    private OperatingMode caOperatingMode;
    private byte[] caRfu2;
    private byte[] publicKeyHeader;
    private byte[] signature;
    private RSAPublicKey rsaPublicKey;

    private Builder() {}

    Builder certType(byte certType) {
      this.certType = CertificateType.fromByte(certType);
      return this;
    }

    Builder structureVersion(byte structureVersion) {
      this.structureVersion = structureVersion;
      return this;
    }

    Builder issuerKeyReference(byte[] issuerKeyReference) {
      this.issuerKeyReference = KeyReference.fromBytes(issuerKeyReference);
      return this;
    }

    Builder caTargetKeyReference(byte[] caTargetKeyReference) {
      this.caTargetKeyReference = KeyReference.fromBytes(caTargetKeyReference);
      return this;
    }

    Builder startDate(byte[] startDate) {
      this.startDate = CertificateUtils.decodeDateBcd(startDate);
      return this;
    }

    Builder caRfu1(byte[] caRfu1) {
      this.caRfu1 = caRfu1.clone();
      return this;
    }

    Builder caRights(byte caRights) {
      this.caRights = CaRights.fromByte(caRights);
      return this;
    }

    Builder caScope(byte caScope) {
      this.caScope = CaScope.fromByte(caScope);
      return this;
    }

    Builder endDate(byte[] endDate) {
      this.endDate = CertificateUtils.decodeDateBcd(endDate);
      return this;
    }

    Builder caTargetAidUnpaddedValue(byte[] caTargetAidUnpaddedValue) {
      this.caTargetAid = Aid.fromUnpaddedValue(caTargetAidUnpaddedValue);
      return this;
    }

    Builder caTargetAid(byte caTargetAidSize, byte[] caTargetAidValue) {
      this.caTargetAid = Aid.fromBytes(caTargetAidSize, caTargetAidValue);
      return this;
    }

    Builder caOperatingMode(byte caOperatingMode) {
      this.caOperatingMode = OperatingMode.fromByte(caOperatingMode);
      return this;
    }

    Builder caRfu2(byte[] caRfu2) {
      this.caRfu2 = caRfu2.clone();
      return this;
    }

    Builder publicKeyHeader(byte[] publicKeyHeader) {
      this.publicKeyHeader = publicKeyHeader.clone();
      return this;
    }

    Builder signature(byte[] signature) {
      this.signature = signature.clone();
      return this;
    }

    Builder rsaPublicKey(RSAPublicKey rsaPublicKey) {
      CertificateUtils.checkRSA2048PublicKey(rsaPublicKey);
      this.rsaPublicKey = rsaPublicKey;
      return this;
    }

    CaCertificate build() {
      return new CaCertificate(this);
    }
  }
}
