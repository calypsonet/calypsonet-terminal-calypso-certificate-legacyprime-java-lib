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

class AidTest {

  // Tests for RFU case (size = 0xFF)

  @Test
  void fromBytes_whenSizeIsFFhAndValueIsAllZeros_shouldReturnRfuAid() {
    // Given
    byte aidSize = (byte) 0xFF;
    byte[] aidValue = new byte[16]; // All zeros

    // When
    Aid result = Aid.fromBytes(aidSize, aidValue);

    // Then
    assertThat(result).isNotNull();
    assertThat(result.isRfu()).isTrue();
    assertThat(result.getSize()).isEqualTo((byte) 0xFF);
  }

  @Test
  void fromBytes_whenSizeIsFFhAndValueIsNotAllZeros_shouldThrowIllegalArgumentException() {
    // Given
    byte aidSize = (byte) 0xFF;
    byte[] aidValue = new byte[16];
    aidValue[5] = 0x01; // One non-zero byte

    // When & Then
    assertThatThrownBy(() -> Aid.fromBytes(aidSize, aidValue))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("When AID size is FFh (RFU), AID value must contain only zero bytes");
  }

  @Test
  void fromBytes_whenSizeIsFFhAndLastByteIsNonZero_shouldThrowIllegalArgumentException() {
    // Given
    byte aidSize = (byte) 0xFF;
    byte[] aidValue = new byte[16];
    aidValue[15] = (byte) 0xFF; // Last byte non-zero

    // When & Then
    assertThatThrownBy(() -> Aid.fromBytes(aidSize, aidValue))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("When AID size is FFh (RFU), AID value must contain only zero bytes");
  }

  @Test
  void isRfu_whenSizeIsFFh_shouldReturnTrue() {
    // Given
    byte aidSize = (byte) 0xFF;
    byte[] aidValue = new byte[16]; // All zeros
    Aid rfuAid = Aid.fromBytes(aidSize, aidValue);

    // When & Then
    assertThat(rfuAid.isRfu()).isTrue();
  }

  @Test
  void isRfu_whenSizeIsNot0xFF_shouldReturnFalse() {
    // Given
    byte[] unpaddedValue = new byte[] {(byte) 0xA0, 0x00, 0x00, 0x00, 0x01};
    Aid aid = Aid.fromUnpaddedValue(unpaddedValue);

    // When & Then
    assertThat(aid.isRfu()).isFalse();
  }

  @Test
  void getUnpaddedValue_whenRfuAid_shouldReturn16Zeros() {
    // Given
    byte aidSize = (byte) 0xFF;
    byte[] aidValue = new byte[16]; // All zeros
    Aid rfuAid = Aid.fromBytes(aidSize, aidValue);

    // When
    byte[] result = rfuAid.getUnpaddedValue();

    // Then
    assertThat(result).hasSize(16).containsOnly((byte) 0x00);
  }

  @Test
  void getPaddedValue_whenRfuAid_shouldReturn16Zeros() {
    // Given
    byte aidSize = (byte) 0xFF;
    byte[] aidValue = new byte[16]; // All zeros
    Aid rfuAid = Aid.fromBytes(aidSize, aidValue);

    // When
    byte[] result = rfuAid.getPaddedValue();

    // Then
    assertThat(result).hasSize(16).containsOnly((byte) 0x00);
  }

  @Test
  void toBytes_whenRfuAid_shouldReturnFFFollowedBy16Zeros() {
    // Given
    byte aidSize = (byte) 0xFF;
    byte[] aidValue = new byte[16]; // All zeros
    Aid rfuAid = Aid.fromBytes(aidSize, aidValue);

    // When
    byte[] result = rfuAid.toBytes();

    // Then
    assertThat(result).hasSize(17);
    assertThat(result[0]).isEqualTo((byte) 0xFF);
    for (int i = 1; i < 17; i++) {
      assertThat(result[i]).isEqualTo((byte) 0x00);
    }
  }

  @Test
  void toString_whenRfuAid_shouldReturnRfuString() {
    // Given
    byte aidSize = (byte) 0xFF;
    byte[] aidValue = new byte[16]; // All zeros
    Aid rfuAid = Aid.fromBytes(aidSize, aidValue);

    // When
    String result = rfuAid.toString();

    // Then
    assertThat(result).isEqualTo("Aid{RFU}");
  }

  @Test
  void equals_whenBothAreRfuAids_shouldReturnTrue() {
    // Given
    byte aidSize = (byte) 0xFF;
    byte[] aidValue = new byte[16]; // All zeros
    Aid rfuAid1 = Aid.fromBytes(aidSize, aidValue);
    Aid rfuAid2 = Aid.fromBytes(aidSize, aidValue);

    // When & Then
    assertThat(rfuAid1).isEqualTo(rfuAid2);
    assertThat(rfuAid1.hashCode()).isEqualTo(rfuAid2.hashCode());
  }

  @Test
  void equals_whenRfuAidComparedWithNormalAid_shouldReturnFalse() {
    // Given
    byte aidSize = (byte) 0xFF;
    byte[] aidValue = new byte[16]; // All zeros
    Aid rfuAid = Aid.fromBytes(aidSize, aidValue);
    byte[] normalValue = new byte[] {(byte) 0xA0, 0x00, 0x00, 0x00, 0x01};
    Aid normalAid = Aid.fromUnpaddedValue(normalValue);

    // When & Then
    assertThat(rfuAid).isNotEqualTo(normalAid);
  }

  // Tests for valid AID creation

  @Test
  void fromBytes_whenSizeIs5AndValueIsValid_shouldReturnAid() {
    // Given
    byte aidSize = 0x05;
    byte[] aidValue = new byte[16];
    aidValue[0] = (byte) 0xA0;
    aidValue[1] = 0x00;
    aidValue[2] = 0x00;
    aidValue[3] = 0x00;
    aidValue[4] = 0x01;

    // When
    Aid result = Aid.fromBytes(aidSize, aidValue);

    // Then
    assertThat(result).isNotNull();
    assertThat(result.getSize()).isEqualTo((byte) 0x05);
    assertThat(result.getUnpaddedValue())
        .hasSize(5)
        .containsExactly((byte) 0xA0, 0x00, 0x00, 0x00, 0x01);
    assertThat(result.getPaddedValue()).hasSize(16);
  }

  @Test
  void fromBytes_whenSizeIs16AndValueIsValid_shouldReturnAid() {
    // Given
    byte aidSize = 0x10; // 16
    byte[] aidValue = new byte[16];
    for (int i = 0; i < 16; i++) {
      aidValue[i] = (byte) (0xA0 + i);
    }

    // When
    Aid result = Aid.fromBytes(aidSize, aidValue);

    // Then
    assertThat(result).isNotNull();
    assertThat(result.getSize()).isEqualTo((byte) 0x10);
    assertThat(result.getUnpaddedValue()).hasSize(16);
  }

  @Test
  void fromBytes_whenSizeIsLessThan5_shouldThrowIllegalArgumentException() {
    // Given
    byte aidSize = 0x04;
    byte[] aidValue = new byte[16];
    aidValue[0] = (byte) 0xA0;

    // When & Then
    assertThatThrownBy(() -> Aid.fromBytes(aidSize, aidValue))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("AID size must be between");
  }

  @Test
  void fromBytes_whenSizeIsGreaterThan16_shouldThrowIllegalArgumentException() {
    // Given
    byte aidSize = 0x11; // 17
    byte[] aidValue = new byte[16];
    aidValue[0] = (byte) 0xA0;

    // When & Then
    assertThatThrownBy(() -> Aid.fromBytes(aidSize, aidValue))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("AID size must be between");
  }

  @Test
  void fromBytes_whenValueIsNull_shouldThrowIllegalArgumentException() {
    // Given
    byte aidSize = 0x0A;

    // When & Then
    assertThatThrownBy(() -> Aid.fromBytes(aidSize, null))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("AID value must be");
  }

  @Test
  void fromBytes_whenValueIsNot16Bytes_shouldThrowIllegalArgumentException() {
    // Given
    byte aidSize = 0x0A;
    byte[] aidValue = new byte[10]; // Wrong size

    // When & Then
    assertThatThrownBy(() -> Aid.fromBytes(aidSize, aidValue))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("AID value must be 16 bytes");
  }

  @Test
  void fromBytes_whenSignificantBytesAreAllZeros_shouldThrowIllegalArgumentException() {
    // Given
    byte aidSize = 0x08;
    byte[] aidValue = new byte[16]; // All zeros

    // When & Then
    assertThatThrownBy(() -> Aid.fromBytes(aidSize, aidValue))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("AID cannot contain only zero bytes");
  }

  // Tests for fromUnpaddedValue

  @Test
  void fromValue_whenUnpaddedValueIsValid_shouldCreateAid() {
    // Given
    byte[] unpaddedValue = new byte[] {(byte) 0xA0, 0x00, 0x00, 0x00, 0x01};

    // When
    Aid result = Aid.fromUnpaddedValue(unpaddedValue);

    // Then
    assertThat(result).isNotNull();
    assertThat(result.getSize()).isEqualTo((byte) 0x05);
    assertThat(result.getUnpaddedValue()).containsExactly((byte) 0xA0, 0x00, 0x00, 0x00, 0x01);
    assertThat(result.getPaddedValue()).hasSize(16);
  }

  @Test
  void fromValue_whenUnpaddedValueIsNull_shouldThrowIllegalArgumentException() {
    // When & Then
    assertThatThrownBy(() -> Aid.fromUnpaddedValue(null))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("AID value cannot be null");
  }

  @Test
  void fromValue_whenUnpaddedValueIsTooShort_shouldThrowIllegalArgumentException() {
    // Given
    byte[] unpaddedValue = new byte[] {(byte) 0xA0, 0x00, 0x00, 0x00};

    // When & Then
    assertThatThrownBy(() -> Aid.fromUnpaddedValue(unpaddedValue))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("AID length must be between");
  }

  @Test
  void fromValue_whenUnpaddedValueIsTooLong_shouldThrowIllegalArgumentException() {
    // Given
    byte[] unpaddedValue = new byte[17];

    // When & Then
    assertThatThrownBy(() -> Aid.fromUnpaddedValue(unpaddedValue))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("AID length must be between");
  }

  @Test
  void fromUnpaddedValue_whenUnpaddedValueIsAllZeros_shouldSetAidSizeToFF() {
    // Given
    byte[] unpaddedValue = new byte[10]; // All zerosAid
    Aid aid = Aid.fromUnpaddedValue(unpaddedValue);

    // When
    byte result = aid.getSize();

    // Then
    assertThat(result).isEqualTo((byte) 0xFF);
  }

  // Tests for getters and serialization

  @Test
  void getValue_shouldReturnUnpaddedUnpaddedPaddedValue() {
    // Given
    byte[] unpaddedValue = new byte[] {(byte) 0xA0, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03};
    Aid aid = Aid.fromUnpaddedValue(unpaddedValue);

    // When
    byte[] result = aid.getUnpaddedValue();

    // Then
    assertThat(result).hasSize(7).containsExactly((byte) 0xA0, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03);
  }

  @Test
  void getUnpaddedValue_whenCreatedFromBytesWithSize5_shouldReturnOnly5Bytes() {
    // Given
    byte aidSize = 0x05;
    byte[] aidValue = new byte[16];
    aidValue[0] = (byte) 0xA0;
    aidValue[1] = 0x00;
    aidValue[2] = 0x00;
    aidValue[3] = 0x00;
    aidValue[4] = 0x01;
    aidValue[5] = (byte) 0xFF; // This should NOT appear in getUnpaddedValue()
    Aid aid = Aid.fromBytes(aidSize, aidValue);

    // When
    byte[] result = aid.getUnpaddedValue();

    // Then
    assertThat(result).hasSize(5).containsExactly((byte) 0xA0, 0x00, 0x00, 0x00, 0x01);
  }

  @Test
  void getUnpaddedValue_whenCreatedFromBytesWithSize16_shouldReturn16Bytes() {
    // Given
    byte aidSize = 0x10; // 16
    byte[] aidValue = new byte[16];
    for (int i = 0; i < 16; i++) {
      aidValue[i] = (byte) (0xA0 + i);
    }
    Aid aid = Aid.fromBytes(aidSize, aidValue);

    // When
    byte[] result = aid.getUnpaddedValue();

    // Then
    assertThat(result).hasSize(16);
    for (int i = 0; i < 16; i++) {
      assertThat(result[i]).isEqualTo((byte) (0xA0 + i));
    }
  }

  @Test
  void getPaddedValue_shouldReturn16Bytes() {
    // Given
    byte[] unpaddedValue = new byte[] {(byte) 0xA0, 0x00, 0x00, 0x00, 0x01};
    Aid aid = Aid.fromUnpaddedValue(unpaddedValue);

    // When
    byte[] result = aid.getPaddedValue();

    // Then
    assertThat(result).hasSize(16);
    assertThat(result[0]).isEqualTo((byte) 0xA0);
    assertThat(result[4]).isEqualTo((byte) 0x01);
    assertThat(result[5]).isEqualTo((byte) 0x00); // Padding
    assertThat(result[15]).isEqualTo((byte) 0x00); // Padding
  }

  @Test
  void getPaddedValue_whenCreatedFromBytesWithSize5_shouldReturn16BytesWithPadding() {
    // Given
    byte aidSize = 0x05;
    byte[] aidValue = new byte[16];
    aidValue[0] = (byte) 0xA0;
    aidValue[1] = 0x00;
    aidValue[2] = 0x00;
    aidValue[3] = 0x00;
    aidValue[4] = 0x01;
    Aid aid = Aid.fromBytes(aidSize, aidValue);

    // When
    byte[] result = aid.getPaddedValue();

    // Then
    assertThat(result).hasSize(16);
    assertThat(result[0]).isEqualTo((byte) 0xA0);
    assertThat(result[1]).isEqualTo((byte) 0x00);
    assertThat(result[2]).isEqualTo((byte) 0x00);
    assertThat(result[3]).isEqualTo((byte) 0x00);
    assertThat(result[4]).isEqualTo((byte) 0x01);
    // All remaining bytes should be zero (padding)
    for (int i = 5; i < 16; i++) {
      assertThat(result[i]).isEqualTo((byte) 0x00);
    }
  }

  @Test
  void getPaddedValue_whenCreatedFromBytesWithSize16_shouldReturn16BytesWithNoExtraPadding() {
    // Given
    byte aidSize = 0x10; // 16
    byte[] aidValue = new byte[16];
    for (int i = 0; i < 16; i++) {
      aidValue[i] = (byte) (0xA0 + i);
    }
    Aid aid = Aid.fromBytes(aidSize, aidValue);

    // When
    byte[] result = aid.getPaddedValue();

    // Then
    assertThat(result).hasSize(16);
    for (int i = 0; i < 16; i++) {
      assertThat(result[i]).isEqualTo((byte) (0xA0 + i));
    }
  }

  @Test
  void getUnpaddedValue_shouldReturnCopy_notOriginalArray() {
    // Given
    byte[] unpaddedValue = new byte[] {(byte) 0xA0, 0x00, 0x00, 0x00, 0x01};
    Aid aid = Aid.fromUnpaddedValue(unpaddedValue);

    // When
    byte[] result = aid.getUnpaddedValue();
    result[0] = (byte) 0xFF; // Modify returned array

    // Then - Original should not be affected
    assertThat(aid.getUnpaddedValue()[0]).isEqualTo((byte) 0xA0);
  }

  @Test
  void getPaddedValue_shouldReturnCopy_notOriginalArray() {
    // Given
    byte[] unpaddedValue = new byte[] {(byte) 0xA0, 0x00, 0x00, 0x00, 0x01};
    Aid aid = Aid.fromUnpaddedValue(unpaddedValue);

    // When
    byte[] result = aid.getPaddedValue();
    result[0] = (byte) 0xFF; // Modify returned array

    // Then - Original should not be affected
    assertThat(aid.getPaddedValue()[0]).isEqualTo((byte) 0xA0);
  }

  @Test
  void toBytes_shouldReturnSizeAndPaddedValue() {
    // Given
    byte[] unpaddedValue = new byte[] {(byte) 0xA0, 0x00, 0x00, 0x00, 0x01};
    Aid aid = Aid.fromUnpaddedValue(unpaddedValue);

    // When
    byte[] result = aid.toBytes();

    // Then
    assertThat(result).hasSize(17);
    assertThat(result[0]).isEqualTo((byte) 0x05); // Size
    assertThat(result[1]).isEqualTo((byte) 0xA0); // First byte of value
    assertThat(result[5]).isEqualTo((byte) 0x01); // Last significant byte
    assertThat(result[6]).isEqualTo((byte) 0x00); // Padding
    assertThat(result[16]).isEqualTo((byte) 0x00); // Padding
  }

  // Tests for matches()

  @Test
  void matches_whenTruncationAllowedAndCaAidStartsWithIssuerAid_shouldReturnTrue() {
    // Given
    byte[] issuerValue = new byte[] {(byte) 0xA0, 0x00, 0x00, 0x00, 0x01};
    byte[] caValue = new byte[] {(byte) 0xA0, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03};
    Aid issuerAid = Aid.fromUnpaddedValue(issuerValue);
    Aid caAid = Aid.fromUnpaddedValue(caValue);
    OperatingMode mode = OperatingMode.TRUNCATION_ALLOWED;

    // When
    boolean result = caAid.matches(issuerAid, mode);

    // Then
    assertThat(result).isTrue();
  }

  @Test
  void matches_whenTruncationAllowedAndCaAidIsShorter_shouldReturnFalse() {
    // Given
    byte[] issuerValue = new byte[] {(byte) 0xA0, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03};
    byte[] caValue = new byte[] {(byte) 0xA0, 0x00, 0x00, 0x00, 0x01};
    Aid issuerAid = Aid.fromUnpaddedValue(issuerValue);
    Aid caAid = Aid.fromUnpaddedValue(caValue);
    OperatingMode mode = OperatingMode.TRUNCATION_ALLOWED;

    // When
    boolean result = caAid.matches(issuerAid, mode);

    // Then
    assertThat(result).isFalse();
  }

  @Test
  void matches_whenTruncationForbiddenAndAidsAreEqual_shouldReturnTrue() {
    // Given
    byte[] value = new byte[] {(byte) 0xA0, 0x00, 0x00, 0x00, 0x01};
    Aid issuerAid = Aid.fromUnpaddedValue(value);
    Aid caAid = Aid.fromUnpaddedValue(value);
    OperatingMode mode = OperatingMode.TRUNCATION_FORBIDDEN;

    // When
    boolean result = caAid.matches(issuerAid, mode);

    // Then
    assertThat(result).isTrue();
  }

  @Test
  void matches_whenTruncationForbiddenAndSizesDifferent_shouldReturnFalse() {
    // Given
    byte[] issuerValue = new byte[] {(byte) 0xA0, 0x00, 0x00, 0x00, 0x01};
    byte[] caValue = new byte[] {(byte) 0xA0, 0x00, 0x00, 0x00, 0x01, 0x02};
    Aid issuerAid = Aid.fromUnpaddedValue(issuerValue);
    Aid caAid = Aid.fromUnpaddedValue(caValue);
    OperatingMode mode = OperatingMode.TRUNCATION_FORBIDDEN;

    // When
    boolean result = caAid.matches(issuerAid, mode);

    // Then
    assertThat(result).isFalse();
  }

  @Test
  void matches_whenIssuerAidIsNull_shouldReturnFalse() {
    // Given
    byte[] caValue = new byte[] {(byte) 0xA0, 0x00, 0x00, 0x00, 0x01};
    Aid caAid = Aid.fromUnpaddedValue(caValue);
    OperatingMode mode = OperatingMode.TRUNCATION_ALLOWED;

    // When
    boolean result = caAid.matches(null, mode);

    // Then
    assertThat(result).isFalse();
  }

  // Tests for equals() and hashCode()

  @Test
  void equals_whenSameAid_shouldReturnTrue() {
    // Given
    byte[] value = new byte[] {(byte) 0xA0, 0x00, 0x00, 0x00, 0x01};
    Aid aid1 = Aid.fromUnpaddedValue(value);
    Aid aid2 = Aid.fromUnpaddedValue(value);

    // When & Then
    assertThat(aid1).isEqualTo(aid2);
    assertThat(aid1.hashCode()).isEqualTo(aid2.hashCode());
  }

  @Test
  void equals_whenDifferentSizes_shouldReturnFalse() {
    // Given
    byte[] value1 = new byte[] {(byte) 0xA0, 0x00, 0x00, 0x00, 0x01};
    byte[] value2 = new byte[] {(byte) 0xA0, 0x00, 0x00, 0x00, 0x01, 0x02};
    Aid aid1 = Aid.fromUnpaddedValue(value1);
    Aid aid2 = Aid.fromUnpaddedValue(value2);

    // When & Then
    assertThat(aid1).isNotEqualTo(aid2);
  }

  @Test
  void equals_whenDifferentValues_shouldReturnFalse() {
    // Given
    byte[] value1 = new byte[] {(byte) 0xA0, 0x00, 0x00, 0x00, 0x01};
    byte[] value2 = new byte[] {(byte) 0xA0, 0x00, 0x00, 0x00, 0x02};
    Aid aid1 = Aid.fromUnpaddedValue(value1);
    Aid aid2 = Aid.fromUnpaddedValue(value2);

    // When & Then
    assertThat(aid1).isNotEqualTo(aid2);
  }

  // Test for toString()

  @Test
  void toString_shouldDisplaySignificantBytes() {
    // Given
    byte[] value = new byte[] {(byte) 0xA0, 0x00, 0x00, 0x00, 0x01};
    Aid aid = Aid.fromUnpaddedValue(value);

    // When
    String result = aid.toString();

    // Then
    assertThat(result).isEqualTo("Aid{A0 00 00 00 01}");
  }
}
