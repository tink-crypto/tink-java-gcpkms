// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink.integration.gcpkms.internal;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.cloud.kms.v1.PublicKey;
import com.google.common.hash.Hashing;
import com.google.protobuf.ByteString;
import com.google.protobuf.Int64Value;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class GcpKmsUtilTest {
  private static final String VALID_KEY_NAME =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions/1";
  private static final String KEY_NAME_WRONG_FORMAT =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions";
  private static final String KEY_NAME_WITHOUT_VERSION =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1";

  private static final ByteString PUBLIC_KEY_PEM =
      ByteString.copyFromUtf8(
          "-----BEGIN PUBLIC KEY-----\n"
              + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+d2qNlHlJ2tG+lA9rP+8Vj/l+l3/\n"
              + "-----END PUBLIC KEY-----\n");

  // --- validateKeyName ---

  @Test
  public void validateKeyName_valid_doesNotThrow() throws Exception {
    GcpKmsUtil.validateKeyName(VALID_KEY_NAME);
  }

  @Test
  public void validateKeyName_null_throws() throws Exception {
    GeneralSecurityException e =
        assertThrows(GeneralSecurityException.class, () -> GcpKmsUtil.validateKeyName(null));
    assertThat(e).hasMessageThat().contains("The keyName is null");
  }

  @Test
  public void validateKeyName_empty_throws() throws Exception {
    GeneralSecurityException e =
        assertThrows(GeneralSecurityException.class, () -> GcpKmsUtil.validateKeyName(""));
    assertThat(e).hasMessageThat().contains("The keyName must follow");
  }

  @Test
  public void validateKeyName_wrongFormat_throws() throws Exception {
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> GcpKmsUtil.validateKeyName(KEY_NAME_WRONG_FORMAT));
    assertThat(e).hasMessageThat().contains("The keyName must follow");
  }

  @Test
  public void validateKeyName_withoutCryptoKeyVersion_throws() throws Exception {
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> GcpKmsUtil.validateKeyName(KEY_NAME_WITHOUT_VERSION));
    assertThat(e).hasMessageThat().contains("The keyName must follow");
  }

  // --- verifyPublicKeyChecksum ---

  @Test
  public void verifyPublicKeyChecksum_matchingChecksum_doesNotThrow() throws Exception {
    long correctCrc32c =
        Hashing.crc32c().hashBytes(PUBLIC_KEY_PEM.asReadOnlyByteBuffer()).padToLong();
    PublicKey publicKey =
        PublicKey.newBuilder()
            .setPemBytes(PUBLIC_KEY_PEM)
            .setPemCrc32C(Int64Value.of(correctCrc32c))
            .build();
    GcpKmsUtil.verifyPublicKeyChecksum(publicKey);
  }

  @Test
  public void verifyPublicKeyChecksum_missingChecksum_throws() throws Exception {
    PublicKey publicKey = PublicKey.newBuilder().setPemBytes(PUBLIC_KEY_PEM).build();
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class, () -> GcpKmsUtil.verifyPublicKeyChecksum(publicKey));
    assertThat(e).hasMessageThat().contains("did not include a checksum");
  }

  @Test
  public void verifyPublicKeyChecksum_mismatchedChecksum_throws() throws Exception {
    long correctCrc32c =
        Hashing.crc32c().hashBytes(PUBLIC_KEY_PEM.asReadOnlyByteBuffer()).padToLong();
    PublicKey publicKey =
        PublicKey.newBuilder()
            .setPemBytes(PUBLIC_KEY_PEM)
            // Corrupt the checksum so it no longer matches the public key.
            .setPemCrc32C(Int64Value.of(correctCrc32c + 1))
            .build();
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class, () -> GcpKmsUtil.verifyPublicKeyChecksum(publicKey));
    assertThat(e).hasMessageThat().contains("does not match the public key");
  }
}
