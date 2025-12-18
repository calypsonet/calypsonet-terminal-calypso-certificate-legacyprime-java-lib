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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class CardCertificateTest {

  private CardCertificate.Builder builder;
  private byte[] issuerKeyReference;
  private Aid cardAid;
  private byte[] cardSerialNumber;
  private byte[] cardIndex;
  private byte[] startDate;
  private byte[] endDate;
  private byte[] cardInfo;
  private byte[] cardRfu;
  private byte[] eccPublicKey;
  private byte[] eccRfu;
  private byte[] signature;

  @BeforeEach
  void setUp() {
    builder = CardCertificate.builder();

    // Initialize test data
    issuerKeyReference = new byte[29];
    issuerKeyReference[0] = 0x0A; // AID size = 10 (valid range 5-16)
    // AID value bytes 1-10 (unpadded)
    for (int i = 1; i <= 10; i++) {
      issuerKeyReference[i] = (byte) (0x01 + i);
    }
    // AID padding bytes 11-16 (must be zeros)
    for (int i = 11; i <= 16; i++) {
      issuerKeyReference[i] = 0x00;
    }
    // Serial number and key ID
    for (int i = 17; i < 29; i++) {
      issuerKeyReference[i] = (byte) (0x01 + i);
    }

    byte[] cardAidValue = new byte[16];
    for (int i = 0; i < 16; i++) {
      cardAidValue[i] = (byte) (0xA0 + i);
    }
    cardAid = Aid.fromUnpaddedValue(cardAidValue);

    cardSerialNumber = new byte[8];
    for (int i = 0; i < 8; i++) {
      cardSerialNumber[i] = (byte) (0x10 + i);
    }

    cardIndex = new byte[] {0x00, 0x00, 0x00, 0x01};

    startDate = new byte[] {0x20, 0x24, 0x01, 0x01}; // 2024-01-01 in BCD
    endDate = new byte[] {0x20, 0x29, 0x12, 0x31}; // 2029-12-31 in BCD

    cardInfo = new byte[7];
    for (int i = 0; i < 7; i++) {
      cardInfo[i] = (byte) (0x20 + i);
    }

    cardRfu = new byte[18];
    for (int i = 0; i < 18; i++) {
      cardRfu[i] = (byte) 0x00;
    }

    eccPublicKey = new byte[64];
    for (int i = 0; i < 64; i++) {
      eccPublicKey[i] = (byte) (0x40 + i);
    }

    eccRfu = new byte[124];
    for (int i = 0; i < 124; i++) {
      eccRfu[i] = (byte) 0x00;
    }

    signature = new byte[256];
    for (int i = 0; i < 256; i++) {
      signature[i] = (byte) (0xFF - i);
    }
  }

  // Tests for getRecoverableDataForSigning()

  @Test
  void getRecoverableDataForSigning_shouldReturn222Bytes() {
    // Given
    CardCertificate certificate =
        builder
            .certType((byte) 0x91)
            .structureVersion((byte) 0x01)
            .issuerKeyReference(issuerKeyReference)
            .cardAid(cardAid)
            .cardSerialNumber(cardSerialNumber)
            .cardIndex(cardIndex)
            .signature(signature)
            .startDate(startDate)
            .endDate(endDate)
            .cardRights((byte) 0x0F)
            .cardInfo(cardInfo)
            .cardRfu(cardRfu)
            .eccPublicKey(eccPublicKey)
            .eccRfu(eccRfu)
            .build();

    // When
    byte[] bytes = certificate.getRecoverableDataForSigning();

    // Then
    assertThat(bytes).hasSize(222);
  }

  @Test
  void getRecoverableDataForSigning_shouldContainCorrectFieldsInCorrectOrder() {
    // Given
    CardCertificate certificate =
        builder
            .certType((byte) 0x91)
            .structureVersion((byte) 0x01)
            .issuerKeyReference(issuerKeyReference)
            .cardAid(cardAid)
            .cardSerialNumber(cardSerialNumber)
            .cardIndex(cardIndex)
            .signature(signature)
            .startDate(startDate)
            .endDate(endDate)
            .cardRights((byte) 0x0F)
            .cardInfo(cardInfo)
            .cardRfu(cardRfu)
            .eccPublicKey(eccPublicKey)
            .eccRfu(eccRfu)
            .build();

    // When
    byte[] bytes = certificate.getRecoverableDataForSigning();

    // Then
    int offset = 0;

    // KCertStartDate (4 bytes)
    for (int i = 0; i < 4; i++) {
      assertThat(bytes[offset++]).isEqualTo(startDate[i]);
    }

    // KCertEndDate (4 bytes)
    for (int i = 0; i < 4; i++) {
      assertThat(bytes[offset++]).isEqualTo(endDate[i]);
    }

    // KCertCardRights (1 byte)
    assertThat(bytes[offset++]).isEqualTo((byte) 0x0F);

    // KCertCardInfo (7 bytes)
    for (int i = 0; i < 7; i++) {
      assertThat(bytes[offset++]).isEqualTo(cardInfo[i]);
    }

    // KCertCardRfu (18 bytes)
    for (int i = 0; i < 18; i++) {
      assertThat(bytes[offset++]).isEqualTo(cardRfu[i]);
    }

    // KCertEccPublicKey (64 bytes)
    for (int i = 0; i < 64; i++) {
      assertThat(bytes[offset++]).isEqualTo(eccPublicKey[i]);
    }

    // KCertEccRfu (124 bytes)
    for (int i = 0; i < 124; i++) {
      assertThat(bytes[offset++]).isEqualTo(eccRfu[i]);
    }

    assertThat(offset).isEqualTo(222);
  }

  @Test
  void getRecoverableDataForSigning_whenStartDateIsNull_shouldFillWithZeros() {
    // Given
    CardCertificate certificate =
        builder
            .certType((byte) 0x91)
            .structureVersion((byte) 0x01)
            .issuerKeyReference(issuerKeyReference)
            .cardAid(cardAid)
            .cardSerialNumber(cardSerialNumber)
            .cardIndex(cardIndex)
            .signature(signature)
            .startDate(null) // Null start date
            .endDate(endDate)
            .cardRights((byte) 0x0F)
            .cardInfo(cardInfo)
            .cardRfu(cardRfu)
            .eccPublicKey(eccPublicKey)
            .eccRfu(eccRfu)
            .build();

    // When
    byte[] bytes = certificate.getRecoverableDataForSigning();

    // Then
    // StartDate is at offset 0
    assertThat(bytes[0]).isEqualTo((byte) 0x00);
    assertThat(bytes[1]).isEqualTo((byte) 0x00);
    assertThat(bytes[2]).isEqualTo((byte) 0x00);
    assertThat(bytes[3]).isEqualTo((byte) 0x00);
  }

  // Tests for toBytesForSigning()

  @Test
  void toBytesForSigning_shouldReturn60Bytes() {
    // Given
    CardCertificate certificate =
        builder
            .certType((byte) 0x91)
            .structureVersion((byte) 0x01)
            .issuerKeyReference(issuerKeyReference)
            .cardAid(cardAid)
            .cardSerialNumber(cardSerialNumber)
            .cardIndex(cardIndex)
            .signature(signature)
            .startDate(startDate)
            .endDate(endDate)
            .cardRights((byte) 0x0F)
            .cardInfo(cardInfo)
            .cardRfu(cardRfu)
            .eccPublicKey(eccPublicKey)
            .eccRfu(eccRfu)
            .build();

    // When
    byte[] bytes = certificate.toBytesForSigning();

    // Then
    assertThat(bytes).hasSize(60);
  }

  @Test
  void toBytesForSigning_shouldContainCorrectFieldsInCorrectOrder() {
    // Given
    CardCertificate certificate =
        builder
            .certType((byte) 0x91)
            .structureVersion((byte) 0x01)
            .issuerKeyReference(issuerKeyReference)
            .cardAid(cardAid)
            .cardSerialNumber(cardSerialNumber)
            .cardIndex(cardIndex)
            .signature(signature)
            .startDate(startDate)
            .endDate(endDate)
            .cardRights((byte) 0x0F)
            .cardInfo(cardInfo)
            .cardRfu(cardRfu)
            .eccPublicKey(eccPublicKey)
            .eccRfu(eccRfu)
            .build();

    // When
    byte[] bytes = certificate.toBytesForSigning();

    // Then
    int offset = 0;

    // KCertType (1 byte)
    assertThat(bytes[offset++]).isEqualTo((byte) 0x91);

    // KCertStructureVersion (1 byte)
    assertThat(bytes[offset++]).isEqualTo((byte) 0x01);

    // KCertIssuerKeyReference (29 bytes)
    for (int i = 0; i < 29; i++) {
      assertThat(bytes[offset++]).isEqualTo(issuerKeyReference[i]);
    }

    // KCertCardAidSize (1 byte)
    assertThat(bytes[offset++]).isEqualTo(cardAid.getSize());

    // KCertCardAidValue (16 bytes)
    for (int i = 0; i < 16; i++) {
      assertThat(bytes[offset++]).isEqualTo(cardAid.getPaddedValue()[i]);
    }

    // KCertCardSerialNumber (8 bytes)
    for (int i = 0; i < 8; i++) {
      assertThat(bytes[offset++]).isEqualTo(cardSerialNumber[i]);
    }

    // KCertCardIndex (4 bytes)
    for (int i = 0; i < 4; i++) {
      assertThat(bytes[offset++]).isEqualTo(cardIndex[i]);
    }

    assertThat(offset).isEqualTo(60);
  }

  @Test
  void toBytesForSigning_whenCardSerialNumberIsNull_shouldFillWithZeros() {
    // Given
    CardCertificate certificate =
        builder
            .certType((byte) 0x91)
            .structureVersion((byte) 0x01)
            .issuerKeyReference(issuerKeyReference)
            .cardAid(cardAid)
            .cardSerialNumber(null) // Null serial number
            .cardIndex(cardIndex)
            .signature(signature)
            .startDate(startDate)
            .endDate(endDate)
            .cardRights((byte) 0x0F)
            .cardInfo(cardInfo)
            .cardRfu(cardRfu)
            .eccPublicKey(eccPublicKey)
            .eccRfu(eccRfu)
            .build();

    // When
    byte[] bytes = certificate.toBytesForSigning();

    // Then
    // CardSerialNumber starts at offset 48 (1 + 1 + 29 + 1 + 16 = 48)
    for (int i = 0; i < 8; i++) {
      assertThat(bytes[48 + i]).isEqualTo((byte) 0x00);
    }
  }

  // Tests for toBytes()

  @Test
  void toBytes_shouldReturn316Bytes() {
    // Given
    CardCertificate certificate =
        builder
            .certType((byte) 0x91)
            .structureVersion((byte) 0x01)
            .issuerKeyReference(issuerKeyReference)
            .cardAid(cardAid)
            .cardSerialNumber(cardSerialNumber)
            .cardIndex(cardIndex)
            .signature(signature)
            .startDate(startDate)
            .endDate(endDate)
            .cardRights((byte) 0x0F)
            .cardInfo(cardInfo)
            .cardRfu(cardRfu)
            .eccPublicKey(eccPublicKey)
            .eccRfu(eccRfu)
            .build();

    // When
    byte[] bytes = certificate.toBytes();

    // Then
    assertThat(bytes).hasSize(316);
  }

  @Test
  void toBytes_shouldContainDataForSigningFollowedBySignature() {
    // Given
    CardCertificate certificate =
        builder
            .certType((byte) 0x91)
            .structureVersion((byte) 0x01)
            .issuerKeyReference(issuerKeyReference)
            .cardAid(cardAid)
            .cardSerialNumber(cardSerialNumber)
            .cardIndex(cardIndex)
            .signature(signature)
            .startDate(startDate)
            .endDate(endDate)
            .cardRights((byte) 0x0F)
            .cardInfo(cardInfo)
            .cardRfu(cardRfu)
            .eccPublicKey(eccPublicKey)
            .eccRfu(eccRfu)
            .build();

    // When
    byte[] bytes = certificate.toBytes();
    byte[] dataForSigning = certificate.toBytesForSigning();

    // Then
    // First 60 bytes should match toBytesForSigning()
    for (int i = 0; i < 60; i++) {
      assertThat(bytes[i]).isEqualTo(dataForSigning[i]);
    }

    // Last 256 bytes should be the signature
    for (int i = 0; i < 256; i++) {
      assertThat(bytes[60 + i]).isEqualTo(signature[i]);
    }
  }

  @Test
  void toBytes_shouldBeIdempotent() {
    // Given
    CardCertificate certificate =
        builder
            .certType((byte) 0x91)
            .structureVersion((byte) 0x01)
            .issuerKeyReference(issuerKeyReference)
            .cardAid(cardAid)
            .cardSerialNumber(cardSerialNumber)
            .cardIndex(cardIndex)
            .signature(signature)
            .startDate(startDate)
            .endDate(endDate)
            .cardRights((byte) 0x0F)
            .cardInfo(cardInfo)
            .cardRfu(cardRfu)
            .eccPublicKey(eccPublicKey)
            .eccRfu(eccRfu)
            .build();

    // When
    byte[] bytes1 = certificate.toBytes();
    byte[] bytes2 = certificate.toBytes();

    // Then
    assertThat(bytes1).isEqualTo(bytes2);
  }

  @Test
  void getRecoverableDataForSigning_shouldBeIdempotent() {
    // Given
    CardCertificate certificate =
        builder
            .certType((byte) 0x91)
            .structureVersion((byte) 0x01)
            .issuerKeyReference(issuerKeyReference)
            .cardAid(cardAid)
            .cardSerialNumber(cardSerialNumber)
            .cardIndex(cardIndex)
            .signature(signature)
            .startDate(startDate)
            .endDate(endDate)
            .cardRights((byte) 0x0F)
            .cardInfo(cardInfo)
            .cardRfu(cardRfu)
            .eccPublicKey(eccPublicKey)
            .eccRfu(eccRfu)
            .build();

    // When
    byte[] bytes1 = certificate.getRecoverableDataForSigning();
    byte[] bytes2 = certificate.getRecoverableDataForSigning();

    // Then
    assertThat(bytes1).isEqualTo(bytes2);
  }
}
