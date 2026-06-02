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
import com.google.crypto.tink.Mac;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import java.security.GeneralSecurityException;
import java.util.regex.Pattern;
import javax.annotation.Nullable;

/**
 * A {@link Mac} that forwards MAC computation and verification requests to a key in <a
 * href="https://cloud.google.com/kms/">Google Cloud KMS</a> using GRPC.
 */
public final class GcpKmsMac implements Mac {

  /** A GRPC-based client to communicate with Google Cloud KMS. */
  @SuppressWarnings("unused")
  private final KeyManagementServiceClient kmsClient;

  /**
   * The location of a CryptoKeyVersion in Google Cloud KMS.
   *
   * <p>Valid values have the format: projects/ * /locations/ * /keyRings/ * /cryptoKeys/ *
   * /cryptoKeyVersions/ *. See https://cloud.google.com/kms/docs/object-hierarchy.
   */
  @SuppressWarnings("unused")
  private final String keyName;

  private GcpKmsMac(KeyManagementServiceClient kmsClient, String keyName) {
    this.kmsClient = kmsClient;
    this.keyName = keyName;
  }

  @Override
  public byte[] computeMac(final byte[] data) {
    throw new UnsupportedOperationException();
  }

  @Override
  public void verifyMac(final byte[] mac, final byte[] data) {
    throw new UnsupportedOperationException();
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
