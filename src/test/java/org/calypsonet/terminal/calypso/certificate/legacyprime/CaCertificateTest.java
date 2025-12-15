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

import java.security.interfaces.RSAPublicKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class CaCertificateTest {

  private CaCertificate.Builder builder;
  private byte[] issuerKeyReference;
  private byte[] caTargetKeyReference;
  private byte[] startDate;
  private byte[] endDate;
  private byte[] caRfu1;
  private byte[] caTargetAidValue;
  private byte[] caRfu2;
  private byte[] publicKeyHeader;
  private byte[] signature;
  private RSAPublicKey rsaPublicKey;

  @BeforeEach
  void setUp() throws Exception {
    builder = CaCertificate.builder();

    // Initialize test data
    issuerKeyReference = new byte[29];
    for (int i = 0; i < 29; i++) {
      issuerKeyReference[i] = (byte) (0x01 + i);
    }

    caTargetKeyReference = new byte[29];
    for (int i = 0; i < 29; i++) {
      caTargetKeyReference[i] = (byte) (0x30 + i);
    }

    startDate = new byte[] {0x20, 0x24, 0x01, 0x01}; // 2024-01-01 in BCD
    endDate = new byte[] {0x20, 0x29, 0x12, 0x31}; // 2029-12-31 in BCD

    caRfu1 = new byte[] {0x00, 0x00, 0x00, 0x00};
    caRfu2 = new byte[] {0x00, 0x00};

    caTargetAidValue = new byte[16];
    for (int i = 0; i < 16; i++) {
      caTargetAidValue[i] = (byte) (0xA0 + i);
    }

    publicKeyHeader = new byte[34];
    for (int i = 0; i < 34; i++) {
      publicKeyHeader[i] = (byte) (0x50 + i);
    }

    signature = new byte[256];
    for (int i = 0; i < 256; i++) {
      signature[i] = (byte) (0xFF - i);
    }

    // Create a mock RSA public key (optional for these tests)
    java.security.KeyPairGenerator keyGen = java.security.KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(2048);
    java.security.KeyPair keyPair = keyGen.generateKeyPair();
    rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
  }

  // Tests for toBytesForSigning()

  @Test
  void toBytesForSigning_shouldReturn128Bytes() {
    // Given
    CaCertificate certificate =
        builder
            .certType((byte) 0x90)
            .structureVersion((byte) 0x01)
            .issuerKeyReference(issuerKeyReference)
            .caTargetKeyReference(caTargetKeyReference)
            .startDate(startDate)
            .caRfu1(caRfu1)
            .caRights((byte) 0x0F)
            .caScope((byte) 0xFF)
            .endDate(endDate)
            .caTargetAidSize((byte) 0x10)
            .caTargetAidValue(caTargetAidValue)
            .caOperatingMode((byte) 0x01)
            .caRfu2(caRfu2)
            .publicKeyHeader(publicKeyHeader)
            .signature(signature)
            .rsaPublicKey(rsaPublicKey)
            .build();

    // When
    byte[] bytes = certificate.toBytesForSigning();

    // Then
    assertThat(bytes).hasSize(128);
  }

  @Test
  void toBytesForSigning_shouldContainCorrectFieldsInCorrectOrder() {
    // Given
    CaCertificate certificate =
        builder
            .certType((byte) 0x90)
            .structureVersion((byte) 0x01)
            .issuerKeyReference(issuerKeyReference)
            .caTargetKeyReference(caTargetKeyReference)
            .startDate(startDate)
            .caRfu1(caRfu1)
            .caRights((byte) 0x0F)
            .caScope((byte) 0xFF)
            .endDate(endDate)
            .caTargetAidSize((byte) 0x10)
            .caTargetAidValue(caTargetAidValue)
            .caOperatingMode((byte) 0x01)
            .caRfu2(caRfu2)
            .publicKeyHeader(publicKeyHeader)
            .signature(signature)
            .rsaPublicKey(rsaPublicKey)
            .build();

    // When
    byte[] bytes = certificate.toBytesForSigning();

    // Then
    int offset = 0;

    // KCertType (1 byte)
    assertThat(bytes[offset++]).isEqualTo((byte) 0x90);

    // KCertStructureVersion (1 byte)
    assertThat(bytes[offset++]).isEqualTo((byte) 0x01);

    // KCertIssuerKeyReference (29 bytes)
    for (int i = 0; i < 29; i++) {
      assertThat(bytes[offset++]).isEqualTo(issuerKeyReference[i]);
    }

    // KCertCaTargetKeyReference (29 bytes)
    for (int i = 0; i < 29; i++) {
      assertThat(bytes[offset++]).isEqualTo(caTargetKeyReference[i]);
    }

    // KCertStartDate (4 bytes)
    for (int i = 0; i < 4; i++) {
      assertThat(bytes[offset++]).isEqualTo(startDate[i]);
    }

    // KCertCaRfu1 (4 bytes)
    for (int i = 0; i < 4; i++) {
      assertThat(bytes[offset++]).isEqualTo(caRfu1[i]);
    }

    // KCertCaRights (1 byte)
    assertThat(bytes[offset++]).isEqualTo((byte) 0x0F);

    // KCertCaScope (1 byte)
    assertThat(bytes[offset++]).isEqualTo((byte) 0xFF);

    // KCertEndDate (4 bytes)
    for (int i = 0; i < 4; i++) {
      assertThat(bytes[offset++]).isEqualTo(endDate[i]);
    }

    // KCertCaTargetAidSize (1 byte)
    assertThat(bytes[offset++]).isEqualTo((byte) 0x10);

    // KCertCaTargetAidValue (16 bytes)
    for (int i = 0; i < 16; i++) {
      assertThat(bytes[offset++]).isEqualTo(caTargetAidValue[i]);
    }

    // KCertCaOperatingMode (1 byte)
    assertThat(bytes[offset++]).isEqualTo((byte) 0x01);

    // KCertCaRfu2 (2 bytes)
    for (int i = 0; i < 2; i++) {
      assertThat(bytes[offset++]).isEqualTo(caRfu2[i]);
    }

    // KCertPublicKeyHeader (34 bytes)
    for (int i = 0; i < 34; i++) {
      assertThat(bytes[offset++]).isEqualTo(publicKeyHeader[i]);
    }

    assertThat(offset).isEqualTo(128);
  }

  @Test
  void toBytesForSigning_whenStartDateIsNull_shouldFillWithZeros() {
    // Given
    CaCertificate certificate =
        builder
            .certType((byte) 0x90)
            .structureVersion((byte) 0x01)
            .issuerKeyReference(issuerKeyReference)
            .caTargetKeyReference(caTargetKeyReference)
            .startDate(null) // Null start date
            .caRfu1(caRfu1)
            .caRights((byte) 0x0F)
            .caScope((byte) 0xFF)
            .endDate(endDate)
            .caTargetAidSize((byte) 0x10)
            .caTargetAidValue(caTargetAidValue)
            .caOperatingMode((byte) 0x01)
            .caRfu2(caRfu2)
            .publicKeyHeader(publicKeyHeader)
            .signature(signature)
            .rsaPublicKey(rsaPublicKey)
            .build();

    // When
    byte[] bytes = certificate.toBytesForSigning();

    // Then
    // StartDate starts at offset 60 (1 + 1 + 29 + 29 = 60)
    assertThat(bytes[60]).isEqualTo((byte) 0x00);
    assertThat(bytes[61]).isEqualTo((byte) 0x00);
    assertThat(bytes[62]).isEqualTo((byte) 0x00);
    assertThat(bytes[63]).isEqualTo((byte) 0x00);
  }

  // Tests for toBytes()

  @Test
  void toBytes_shouldReturn384Bytes() {
    // Given
    CaCertificate certificate =
        builder
            .certType((byte) 0x90)
            .structureVersion((byte) 0x01)
            .issuerKeyReference(issuerKeyReference)
            .caTargetKeyReference(caTargetKeyReference)
            .startDate(startDate)
            .caRfu1(caRfu1)
            .caRights((byte) 0x0F)
            .caScope((byte) 0xFF)
            .endDate(endDate)
            .caTargetAidSize((byte) 0x10)
            .caTargetAidValue(caTargetAidValue)
            .caOperatingMode((byte) 0x01)
            .caRfu2(caRfu2)
            .publicKeyHeader(publicKeyHeader)
            .signature(signature)
            .rsaPublicKey(rsaPublicKey)
            .build();

    // When
    byte[] bytes = certificate.toBytes();

    // Then
    assertThat(bytes).hasSize(384);
  }

  @Test
  void toBytes_shouldContainDataForSigningFollowedBySignature() {
    // Given
    CaCertificate certificate =
        builder
            .certType((byte) 0x90)
            .structureVersion((byte) 0x01)
            .issuerKeyReference(issuerKeyReference)
            .caTargetKeyReference(caTargetKeyReference)
            .startDate(startDate)
            .caRfu1(caRfu1)
            .caRights((byte) 0x0F)
            .caScope((byte) 0xFF)
            .endDate(endDate)
            .caTargetAidSize((byte) 0x10)
            .caTargetAidValue(caTargetAidValue)
            .caOperatingMode((byte) 0x01)
            .caRfu2(caRfu2)
            .publicKeyHeader(publicKeyHeader)
            .signature(signature)
            .rsaPublicKey(rsaPublicKey)
            .build();

    // When
    byte[] bytes = certificate.toBytes();
    byte[] dataForSigning = certificate.toBytesForSigning();

    // Then
    // First 128 bytes should match toBytesForSigning()
    for (int i = 0; i < 128; i++) {
      assertThat(bytes[i]).isEqualTo(dataForSigning[i]);
    }

    // Last 256 bytes should be the signature
    for (int i = 0; i < 256; i++) {
      assertThat(bytes[128 + i]).isEqualTo(signature[i]);
    }
  }

  @Test
  void toBytes_shouldBeIdempotent() {
    // Given
    CaCertificate certificate =
        builder
            .certType((byte) 0x90)
            .structureVersion((byte) 0x01)
            .issuerKeyReference(issuerKeyReference)
            .caTargetKeyReference(caTargetKeyReference)
            .startDate(startDate)
            .caRfu1(caRfu1)
            .caRights((byte) 0x0F)
            .caScope((byte) 0xFF)
            .endDate(endDate)
            .caTargetAidSize((byte) 0x10)
            .caTargetAidValue(caTargetAidValue)
            .caOperatingMode((byte) 0x01)
            .caRfu2(caRfu2)
            .publicKeyHeader(publicKeyHeader)
            .signature(signature)
            .rsaPublicKey(rsaPublicKey)
            .build();

    // When
    byte[] bytes1 = certificate.toBytes();
    byte[] bytes2 = certificate.toBytes();

    // Then
    assertThat(bytes1).isEqualTo(bytes2);
  }
}
