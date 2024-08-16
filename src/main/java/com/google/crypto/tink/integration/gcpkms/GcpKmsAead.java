// Copyright 2017 Google Inc.
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

import com.google.api.services.cloudkms.v1.CloudKMS;
import com.google.api.services.cloudkms.v1.model.DecryptRequest;
import com.google.api.services.cloudkms.v1.model.DecryptResponse;
import com.google.api.services.cloudkms.v1.model.EncryptRequest;
import com.google.api.services.cloudkms.v1.model.EncryptResponse;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.common.hash.Hashing;
import com.google.crypto.tink.Aead;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.protobuf.ByteString;
import com.google.protobuf.Int64Value;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.regex.Pattern;
import javax.annotation.Nullable;

/**
 * An {@link Aead} that forwards encryption/decryption requests to a key in <a
 * href="https://cloud.google.com/kms/">Google Cloud KMS</a>.
 *
 * <p>As of August 2017, Google Cloud KMS supports only AES-256-GCM keys.
 *
 * @since 1.0.0
 */
public final class GcpKmsAead implements Aead {
  /** An HTTP-based client to communicate with Google Cloud KMS. */
  private final CloudKMS kmsClient;

  // The location of a CryptoKey in Google Cloud KMS.
  // Valid values have this format: projects/*/locations/*/keyRings/*/cryptoKeys/*.
  // See https://cloud.google.com/kms/docs/object-hierarchy.
  private final String keyName;

  public GcpKmsAead(CloudKMS kmsClient, String keyName) {
    this.kmsClient = kmsClient;
    this.keyName = keyName;
  }

  @Override
  public byte[] encrypt(final byte[] plaintext, final byte[] associatedData)
      throws GeneralSecurityException {
    try {
      EncryptRequest request =
          new EncryptRequest()
              .encodePlaintext(plaintext)
              .setPlaintextCrc32c(
                  Hashing.crc32c().hashBytes(toNonNullableByteArray(plaintext)).padToLong())
              .encodeAdditionalAuthenticatedData(associatedData)
              .setAdditionalAuthenticatedDataCrc32c(
                  Hashing.crc32c().hashBytes(toNonNullableByteArray(associatedData)).padToLong());
      EncryptResponse response =
          this.kmsClient
              .projects()
              .locations()
              .keyRings()
              .cryptoKeys()
              .encrypt(this.keyName, request)
              .execute();

      if (!keyVersionToKeyName(response.getName()).equals(this.keyName)) {
        throw new GeneralSecurityException(
            "The key name in the response does not match the requested key name.");
      }
      if (response.getVerifiedPlaintextCrc32c() == null || !response.getVerifiedPlaintextCrc32c()) {
        throw new GeneralSecurityException("Verifying the provided plaintext checksum failed.");
      }

      if (response.getVerifiedAdditionalAuthenticatedDataCrc32c() == null
          || !response.getVerifiedAdditionalAuthenticatedDataCrc32c()) {
        throw new GeneralSecurityException(
            "Verifying the provided associated data checksum failed.");
      }

      byte[] ciphertext = toNonNullableByteArray(response.decodeCiphertext());
      long ciphertextCrc32c = Hashing.crc32c().hashBytes(ciphertext).padToLong();
      if (response.getCiphertextCrc32c() != ciphertextCrc32c) {
        throw new GeneralSecurityException("Ciphertext checksum mismatch.");
      }

      return ciphertext;
    } catch (IOException e) {
      throw new GeneralSecurityException("encryption failed", e);
    }
  }

  @Override
  public byte[] decrypt(final byte[] ciphertext, final byte[] associatedData)
      throws GeneralSecurityException {
    try {
      DecryptRequest request =
          new DecryptRequest()
              .encodeCiphertext(ciphertext)
              .setCiphertextCrc32c(
                  Hashing.crc32c().hashBytes(toNonNullableByteArray(ciphertext)).padToLong())
              .encodeAdditionalAuthenticatedData(associatedData)
              .setAdditionalAuthenticatedDataCrc32c(
                  Hashing.crc32c().hashBytes(toNonNullableByteArray(associatedData)).padToLong());
      DecryptResponse response =
          this.kmsClient
              .projects()
              .locations()
              .keyRings()
              .cryptoKeys()
              .decrypt(this.keyName, request)
              .execute();

      byte[] plaintext = toNonNullableByteArray(response.decodePlaintext());
      long plaintextCrc32c = Hashing.crc32c().hashBytes(plaintext).padToLong();
      if (response.getPlaintextCrc32c() != plaintextCrc32c) {
        throw new GeneralSecurityException("Plaintext checksum mismatch.");
      }
      return plaintext;
    } catch (IOException e) {
      throw new GeneralSecurityException("decryption failed", e);
    }
  }

  private static final byte[] EMPTY_BYTE_ARRAY = new byte[0];

  private static byte[] toNonNullableByteArray(byte[] data) {
    if (data == null) {
      return EMPTY_BYTE_ARRAY;
    } else {
      return data;
    }
  }

  private static final String KEY_NAME_DELIMITER = "/";

  /**
   * Converts a resource ID that specifies a key version into a key name. This is done by removing
   * the last two elements which specify the key version.
   *
   * <p>If the resource ID does not match the format of a key version, the input is returned
   * unmodified.
   *
   * <p>For reference, see
   * https://cloud.google.com/kms/docs/resource-hierarchy#retrieve_resource_id.
   */
  private static String keyVersionToKeyName(String keyVersion) {
    String[] parts = keyVersion.split(KEY_NAME_DELIMITER);
    if (parts.length != 10
        || !parts[0].equals("projects")
        || !parts[2].equals("locations")
        || !parts[4].equals("keyRings")
        || !parts[6].equals("cryptoKeys")
        || !parts[8].equals("cryptoKeyVersions")) {
      return keyVersion;
    }
    return String.join(KEY_NAME_DELIMITER, Arrays.asList(parts).subList(0, 8));
  }

  /**
   * An {@link Aead} that forwards encryption/decryption requests to a key in <a
   * href="https://cloud.google.com/kms/">Google Cloud KMS</a> using GRPC.
   */
  private static final class GcpKmsAeadGrpc implements Aead {

    /** A GRPC-based client to communicate with Google Cloud KMS. */
    private final KeyManagementServiceClient kmsClient;

    // The location of a CryptoKey in Google Cloud KMS.
    // Valid values have this format: projects/*/locations/*/keyRings/*/cryptoKeys/*.
    // See https://cloud.google.com/kms/docs/object-hierarchy.
    private final String keyName;

    private GcpKmsAeadGrpc(KeyManagementServiceClient kmsClient, String keyName) {
      this.kmsClient = kmsClient;
      this.keyName = keyName;
    }

    @Override
    public byte[] encrypt(final byte[] plaintext, final byte[] associatedData)
        throws GeneralSecurityException {
      try {
        com.google.cloud.kms.v1.EncryptRequest encryptRequest =
            com.google.cloud.kms.v1.EncryptRequest.newBuilder()
                .setName(keyName)
                .setPlaintext(ByteString.copyFrom(plaintext))
                .setPlaintextCrc32C(
                    Int64Value.of(Hashing.crc32c().hashBytes(plaintext).padToLong()))
                .setAdditionalAuthenticatedData(ByteString.copyFrom(associatedData))
                .setAdditionalAuthenticatedDataCrc32C(
                    Int64Value.of(Hashing.crc32c().hashBytes(associatedData).padToLong()))
                .build();

        com.google.cloud.kms.v1.EncryptResponse encResponse = kmsClient.encrypt(encryptRequest);

        if (!keyVersionToKeyName(encResponse.getName()).equals(keyName)) {
          throw new GeneralSecurityException(
              "The key name in the response does not match the requested key name.");
        }
        if (!encResponse.getVerifiedPlaintextCrc32C()) {
          throw new GeneralSecurityException("Verifying the provided plaintext checksum failed.");
        }

        if (!encResponse.getVerifiedAdditionalAuthenticatedDataCrc32C()) {
          throw new GeneralSecurityException(
              "Verifying the provided associated data checksum failed.");
        }

        byte[] ciphertext = encResponse.getCiphertext().toByteArray();

        long ciphertextCrc = Hashing.crc32c().hashBytes(ciphertext).padToLong();
        if (ciphertextCrc != encResponse.getCiphertextCrc32C().getValue()) {
          throw new GeneralSecurityException("Ciphertext checksum mismatch.");
        }

        return ciphertext;
      } catch (RuntimeException e) {
        throw new GeneralSecurityException("encryption failed", e);
      }
    }

    @Override
    public byte[] decrypt(final byte[] ciphertext, final byte[] associatedData)
        throws GeneralSecurityException {
      try {
        com.google.cloud.kms.v1.DecryptRequest decryptRequest =
            com.google.cloud.kms.v1.DecryptRequest.newBuilder()
                .setName(keyName)
                .setCiphertext(ByteString.copyFrom(ciphertext))
                .setCiphertextCrc32C(
                    Int64Value.of(Hashing.crc32c().hashBytes(ciphertext).padToLong()))
                .setAdditionalAuthenticatedData(ByteString.copyFrom(associatedData))
                .setAdditionalAuthenticatedDataCrc32C(
                    Int64Value.of(Hashing.crc32c().hashBytes(associatedData).padToLong()))
                .build();

        com.google.cloud.kms.v1.DecryptResponse decResponse = kmsClient.decrypt(decryptRequest);

        byte[] plaintext = decResponse.getPlaintext().toByteArray();

        long plaintextCrc = Hashing.crc32c().hashBytes(plaintext).padToLong();
        if (plaintextCrc != decResponse.getPlaintextCrc32C().getValue()) {
          throw new GeneralSecurityException("Plaintext checksum mismatch.");
        }

        return plaintext;
      } catch (RuntimeException e) {
        throw new GeneralSecurityException("decryption failed", e);
      }
    }
  }

  /**
   * A Builder to create an Aead backed by GCP Cloud KMS.
   *
   * <p>If {@link #setKeyManagementServiceClient} is used, the Aead will communicate with Cloud KMS
   * via gRPC given a {@link KeyManagementServiceClient} instance. If {@link #setCloudKms} is used,
   * the Aead will communicate with Cloud KMS via HTTP given a {@link CloudKMS} instance.
   *
   * <p>For new users we recommend using {@link #setKeyManagementServiceClient}.
   */
  public static final class Builder {
    @Nullable private String keyName = null;
    @Nullable private CloudKMS kmsClientHttp = null;
    @Nullable private KeyManagementServiceClient kmsClientGrpc = null;
    private static final String KEY_NAME_PATTERN =
        "projects/([^/]+)/locations/([a-zA-Z0-9_-]{1,63})/keyRings/"
            + "[a-zA-Z0-9_-]{1,63}/cryptoKeys/[a-zA-Z0-9_-]{1,63}";
    private static final Pattern KEY_NAME_MATCHER = Pattern.compile(KEY_NAME_PATTERN);

    private Builder() {}

    /** Set the ResourceName of the KMS key. */
    @CanIgnoreReturnValue
    public Builder setKeyName(String keyName) {
      this.keyName = keyName;
      return this;
    }

    /** Set the CloudKms object. */
    @CanIgnoreReturnValue
    public Builder setCloudKms(CloudKMS cloudKms) {
      this.kmsClientHttp = cloudKms;
      return this;
    }

    /** Set the KeyManagementServiceClient object. */
    @CanIgnoreReturnValue
    public Builder setKeyManagementServiceClient(KeyManagementServiceClient kmsClient) {
      this.kmsClientGrpc = kmsClient;
      return this;
    }

    public Aead build() throws GeneralSecurityException {
      if (keyName == null) {
        throw new GeneralSecurityException("The keyName is null.");
      }

      if (keyName.isEmpty()) {
        throw new GeneralSecurityException("The keyName is empty.");
      }

      if (!KEY_NAME_MATCHER.matcher(keyName).matches()) {
        throw new GeneralSecurityException("The keyName must follow " + KEY_NAME_PATTERN);
      }

      if (kmsClientGrpc == null && kmsClientHttp == null) {
        throw new GeneralSecurityException(
            "Either the CloudKMS or the KeyManagementServiceClient object must be provided.");
      }

      if (kmsClientGrpc != null && kmsClientHttp != null) {
        throw new GeneralSecurityException(
            "Either the CloudKMS or the KeyManagementServiceClient object must be provided.");
      }

      if (kmsClientHttp != null) {
        return new GcpKmsAead(kmsClientHttp, keyName);
      }

      return new GcpKmsAeadGrpc(kmsClientGrpc, keyName);
    }
  }

  public static Builder builder() {
    return new Builder();
  }
}
