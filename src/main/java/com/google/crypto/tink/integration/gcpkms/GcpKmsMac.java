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

package com.google.crypto.tink.integration.gcpkms;

import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.MacSignRequest;
import com.google.cloud.kms.v1.MacSignResponse;
import com.google.cloud.kms.v1.MacVerifyRequest;
import com.google.cloud.kms.v1.MacVerifyResponse;
import com.google.common.hash.Hashing;
import com.google.crypto.tink.Mac;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.protobuf.ByteString;
import com.google.protobuf.Int64Value;
import java.security.GeneralSecurityException;
import java.util.regex.Pattern;
import javax.annotation.Nullable;

/**
 * A {@link Mac} that forwards MAC computation and verification requests to a key in <a
 * href="https://cloud.google.com/kms/">Google Cloud KMS</a> using GRPC.
 *
 * <p>Note that this MAC uses Cloud KMS as a crypto oracle for each operation.
 */
public final class GcpKmsMac implements Mac {

  /** Maximum size of the data that can be used for MAC computation/verification. */
  static final int MAX_MAC_DATA_SIZE = 64 * 1024;

  /** Maximum size of the MAC that can be verified. */
  static final int MAX_MAC_VALUE_SIZE = 64;

  /** A GRPC-based client to communicate with Google Cloud KMS. */
  private final KeyManagementServiceClient kmsClient;

  /**
   * The location of a CryptoKeyVersion in Google Cloud KMS.
   *
   * <p>Valid values have the format: projects/ * /locations/ * /keyRings/ * /cryptoKeys/ *
   * /cryptoKeyVersions/ *. See https://cloud.google.com/kms/docs/object-hierarchy.
   */
  private final String keyName;

  private GcpKmsMac(KeyManagementServiceClient kmsClient, String keyName) {
    this.kmsClient = kmsClient;
    this.keyName = keyName;
  }

  @Override
  public byte[] computeMac(final byte[] data) throws GeneralSecurityException {
    if (data.length > MAX_MAC_DATA_SIZE) {
      throw new GeneralSecurityException(
          "The data size is larger than the allowed size: " + MAX_MAC_DATA_SIZE);
    }
    try {
      MacSignRequest request =
          MacSignRequest.newBuilder()
              .setName(keyName)
              .setData(ByteString.copyFrom(data))
              .setDataCrc32C(Int64Value.of(Hashing.crc32c().hashBytes(data).padToLong()))
              .build();

      MacSignResponse response = kmsClient.macSign(request);

      if (!response.getName().equals(keyName)) {
        throw new GeneralSecurityException(
            "The key name in the response does not match the requested key name.");
      }
      if (!response.getVerifiedDataCrc32C()) {
        throw new GeneralSecurityException("Checking the input checksum failed.");
      }
      long macCrc32c =
          Hashing.crc32c().hashBytes(response.getMac().asReadOnlyByteBuffer()).padToLong();
      if (macCrc32c != response.getMacCrc32C().getValue()) {
        throw new GeneralSecurityException("MAC checksum mismatch.");
      }

      return response.getMac().toByteArray();
    } catch (RuntimeException e) {
      throw new GeneralSecurityException("GCP KMS MacSign failed.", e);
    }
  }

  @Override
  public void verifyMac(final byte[] mac, final byte[] data) throws GeneralSecurityException {
    if (data.length > MAX_MAC_DATA_SIZE) {
      throw new GeneralSecurityException(
          "The data size is larger than the allowed size: " + MAX_MAC_DATA_SIZE);
    }
    if (mac.length > MAX_MAC_VALUE_SIZE) {
      throw new GeneralSecurityException(
          "The MAC size is larger than the allowed size: " + MAX_MAC_VALUE_SIZE);
    }
    try {
      MacVerifyRequest request =
          MacVerifyRequest.newBuilder()
              .setName(keyName)
              .setData(ByteString.copyFrom(data))
              .setDataCrc32C(Int64Value.of(Hashing.crc32c().hashBytes(data).padToLong()))
              .setMac(ByteString.copyFrom(mac))
              .setMacCrc32C(Int64Value.of(Hashing.crc32c().hashBytes(mac).padToLong()))
              .build();

      MacVerifyResponse response = kmsClient.macVerify(request);

      if (!response.getName().equals(keyName)) {
        throw new GeneralSecurityException(
            "The key name in the response does not match the requested key name.");
      }
      if (!response.getVerifiedDataCrc32C()) {
        throw new GeneralSecurityException("Checking the input data checksum failed.");
      }
      if (!response.getVerifiedMacCrc32C()) {
        throw new GeneralSecurityException("Checking the MAC checksum failed.");
      }
      if (!response.getSuccess()) {
        throw new GeneralSecurityException("MAC verification failed.");
      }
      if (response.getVerifiedSuccessIntegrity() != response.getSuccess()) {
        throw new GeneralSecurityException("Checking the verification result integrity failed.");
      }
    } catch (RuntimeException e) {
      throw new GeneralSecurityException("GCP KMS MacVerify failed.", e);
    }
  }

  /** A Builder to create a {@link Mac} that communicates with Cloud KMS via gRPC. */
  public static final class Builder {
    @Nullable private String keyName = null;
    @Nullable private KeyManagementServiceClient kmsClient = null;
    private static final String KEY_NAME_PATTERN =
        "projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+/cryptoKeyVersions/.*";
    private static final Pattern KEY_NAME_MATCHER = Pattern.compile(KEY_NAME_PATTERN);

    private Builder() {}

    /** Set the ResourceName of the KMS key version. */
    @CanIgnoreReturnValue
    public Builder setKeyName(String keyName) {
      this.keyName = keyName;
      return this;
    }

    /** Set the KeyManagementServiceClient object. */
    @CanIgnoreReturnValue
    public Builder setKeyManagementServiceClient(KeyManagementServiceClient kmsClient) {
      this.kmsClient = kmsClient;
      return this;
    }

    public Mac build() throws GeneralSecurityException {
      if (keyName == null) {
        throw new GeneralSecurityException("The keyName is null.");
      }
      if (!KEY_NAME_MATCHER.matcher(keyName).matches()) {
        throw new GeneralSecurityException("The keyName must follow " + KEY_NAME_PATTERN);
      }
      if (kmsClient == null) {
        throw new GeneralSecurityException("The KeyManagementServiceClient object is null.");
      }
      return new GcpKmsMac(kmsClient, keyName);
    }
  }

  public static Builder builder() {
    return new Builder();
  }
}
