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

import com.google.cloud.kms.v1.ChecksummedData;
import com.google.cloud.kms.v1.GetPublicKeyRequest;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.PublicKey;
import com.google.common.hash.Hashing;
import com.google.common.io.BaseEncoding;
import com.google.protobuf.ByteString;
import com.google.protobuf.Int64Value;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.regex.Pattern;

/** Helper functions shared by the Google Cloud KMS integration, for internal use only. */
public final class GcpKmsUtil {

  private static final String KEY_NAME_PATTERN =
      "projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+/cryptoKeyVersions/.*";
  private static final Pattern KEY_NAME_MATCHER = Pattern.compile(KEY_NAME_PATTERN);

  /**
   * Validates that {@code keyName} is a well-formed Cloud KMS CryptoKeyVersion resource name.
   *
   * <p>Valid values have the format: projects/ * /locations/ * /keyRings/ * /cryptoKeys/ *
   * /cryptoKeyVersions/ *. See https://cloud.google.com/kms/docs/object-hierarchy.
   */
  public static void validateKeyName(String keyName) throws GeneralSecurityException {
    if (keyName == null) {
      throw new GeneralSecurityException("The keyName is null.");
    }
    if (!KEY_NAME_MATCHER.matcher(keyName).matches()) {
      throw new GeneralSecurityException("The keyName must follow " + KEY_NAME_PATTERN);
    }
  }

  /**
   * Verifies that the CRC32C checksum returned by KMS matches the public key, to detect corruption
   * of the {@code GetPublicKey} response in transit.
   */
  public static void verifyPublicKeyChecksum(PublicKey publicKey) throws GeneralSecurityException {
    if (!publicKey.getPublicKey().hasCrc32CChecksum()) {
      throw new GeneralSecurityException("KMS GetPublicKey response did not include a checksum.");
    }
    long computedCrc32c =
        Hashing.crc32c()
            .hashBytes(publicKey.getPublicKey().getData().asReadOnlyByteBuffer())
            .padToLong();
    if (computedCrc32c != publicKey.getPublicKey().getCrc32CChecksum().getValue()) {
      throw new GeneralSecurityException(
          "The GetPublicKey checksum does not match the public key.");
    }
  }

  /** Wraps the given bytes together with their CRC32C checksum, as GetPublicKey returns. */
  public static ChecksummedData checksummedData(ByteString data) {
    return ChecksummedData.newBuilder()
        .setData(data)
        .setCrc32CChecksum(
            Int64Value.of(Hashing.crc32c().hashBytes(data.asReadOnlyByteBuffer()).padToLong()))
        .build();
  }

  /**
   * Wraps raw ML-DSA public key bytes in a PEM-encoded SubjectPublicKeyInfo, exactly as Cloud KMS
   * GetPublicKey returns for ML-DSA keys.
   */
  public static ByteString mlDsaPublicKeyPem(String preambleHex, ByteString rawKey) {
    ByteString spki =
        ByteString.copyFrom(BaseEncoding.base16().lowerCase().decode(preambleHex)).concat(rawKey);
    String base64 = Base64.getEncoder().encodeToString(spki.toByteArray());
    StringBuilder pem = new StringBuilder("-----BEGIN PUBLIC KEY-----\n");
    for (int i = 0; i < base64.length(); i += 64) {
      pem.append(base64, i, Math.min(i + 64, base64.length())).append('\n');
    }
    pem.append("-----END PUBLIC KEY-----\n");
    return ByteString.copyFromUtf8(pem.toString());
  }

  /**
   * Fetches the public key for {@code keyName} from KMS and verifies its integrity.
   *
   * <p>The key is initially requested in PEM format, but also falls back to NIST_PQC format for
   * keys that do not support PEM (e.g., SLH-DSA).
   */
  public static PublicKey fetchPublicKey(KeyManagementServiceClient kmsClient, String keyName)
      throws GeneralSecurityException {
    PublicKey publicKey;
    GetPublicKeyRequest.Builder requestBuilder = GetPublicKeyRequest.newBuilder().setName(keyName);

    try {
      publicKey =
          kmsClient.getPublicKey(
              requestBuilder.setPublicKeyFormat(PublicKey.PublicKeyFormat.PEM).build());
    } catch (RuntimeException e) {
      // Keys that do not support PEM (e.g. SLH-DSA) report this; retry in NIST_PQC format.
      if (e.getMessage() == null || !e.getMessage().contains("Only NIST_PQC format is supported")) {
        throw new GeneralSecurityException("The KMS GetPublicKey failed.", e);
      }
      try {
        publicKey =
            kmsClient.getPublicKey(
                requestBuilder.setPublicKeyFormat(PublicKey.PublicKeyFormat.NIST_PQC).build());
      } catch (RuntimeException e2) {
        throw new GeneralSecurityException("The KMS GetPublicKey failed.", e2);
      }
    }

    // Verify the integrity of the fetched public key before relying on it.
    if (!publicKey.getName().equals(keyName)) {
      throw new GeneralSecurityException(
          "The key name in the response does not match the requested key name.");
    }
    verifyPublicKeyChecksum(publicKey);

    return publicKey;
  }

  private GcpKmsUtil() {}
}
