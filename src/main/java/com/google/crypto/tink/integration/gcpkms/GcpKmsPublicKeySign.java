// Copyright 2024 Google LLC
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

import com.google.cloud.kms.v1.AsymmetricSignRequest;
import com.google.cloud.kms.v1.AsymmetricSignResponse;
import com.google.cloud.kms.v1.CryptoKeyVersion;
import com.google.cloud.kms.v1.Digest;
import com.google.cloud.kms.v1.GetPublicKeyRequest;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.ProtectionLevel;
import com.google.cloud.kms.v1.PublicKey;
import com.google.common.hash.Hashing;
import com.google.crypto.tink.PublicKeySign;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.protobuf.ByteString;
import com.google.protobuf.Int64Value;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.regex.Pattern;
import javax.annotation.Nullable;

/**
 * A {@link PublicKeySign} that forwards asymmetric sign requests to a key in <a
 * href="https://cloud.google.com/kms/">Google Cloud KMS</a> using GRPC.
 */
public final class GcpKmsPublicKeySign implements PublicKeySign {

  /** Maximum size of the data that can be signed. */
  private static final int MAX_SIGN_DATA_SIZE = 64 * 1024;

  /** A GRPC-based client to communicate with Google Cloud KMS. */
  private final KeyManagementServiceClient kmsClient;

  /**
   * The location of a CryptoKey in Google Cloud KMS.
   *
   * <p>Valid values have the format: projects/ * /locations/ * /keyRings/ * /cryptoKeys/ *
   * /cryptoKeyVersions/ *. See https://cloud.google.com/kms/docs/object-hierarchy.
   */
  private final String keyName;

  /** Read from KMS, publicKey contains the public key itself and some information about the key. */
  private final PublicKey publicKey;

  private GcpKmsPublicKeySign(
      KeyManagementServiceClient kmsClient, String keyName, PublicKey publicKey) {
    this.keyName = keyName;
    this.kmsClient = kmsClient;
    this.publicKey = publicKey;
  }

  @Override
  public byte[] sign(final byte[] data) throws GeneralSecurityException {
    if (data.length > MAX_SIGN_DATA_SIZE) {
      throw new GeneralSecurityException(
          "The data size is larger than the allowed size: " + MAX_SIGN_DATA_SIZE);
    }

    AsymmetricSignRequest.Builder builder = AsymmetricSignRequest.newBuilder().setName(keyName);
    if (requiresDataForSign(publicKey.getAlgorithm(), publicKey.getProtectionLevel())) {
      builder
          .setData(ByteString.copyFrom(data))
          .setDataCrc32C(Int64Value.of(Hashing.crc32c().hashBytes(data).padToLong()));
    } else {
      Digest digest = computeDigest(data, publicKey.getAlgorithm());
      builder
          .setDigest(digest)
          .setDigestCrc32C(
              Int64Value.of(Hashing.crc32c().hashBytes(digest.toByteArray()).padToLong()));
    }

    try {
      AsymmetricSignResponse response = kmsClient.asymmetricSign(builder.build());
      // Perform integrity checks.
      if (!response.getName().equals(keyName)) {
        throw new GeneralSecurityException(
            "The key name in the response does not match the requested key name.");
      }
      if (!response.getVerifiedDigestCrc32C() && !response.getVerifiedDataCrc32C()) {
        throw new GeneralSecurityException("Checking the input checksum failed.");
      }

      long signatureCrc32c =
          Hashing.crc32c().hashBytes(response.getSignature().asReadOnlyByteBuffer()).padToLong();
      if (signatureCrc32c != response.getSignatureCrc32C().getValue()) {
        throw new GeneralSecurityException("Signature checksum mismatch.");
      }
      // Return the signature.
      return response.getSignature().toByteArray();
    } catch (RuntimeException e) {
      throw new GeneralSecurityException("Asymmetric sign failed. ", e);
    }
  }

  /**
   * Some AsymmetricSign algorithms require data as input and some other operate on a digest of the
   * data. This method determines if data itself is required for signing and returns true if so.
   */
  boolean requiresDataForSign(
      CryptoKeyVersion.CryptoKeyVersionAlgorithm algorithm, ProtectionLevel protectionLevel) {
    // Operate on the data if the algorithm is one of the following:
    switch (algorithm) {
      case RSA_SIGN_RAW_PKCS1_2048:
      case RSA_SIGN_RAW_PKCS1_3072:
      case RSA_SIGN_RAW_PKCS1_4096:
      case EC_SIGN_ED25519:
        return true;
      default:
        break;
    }

    // or the protection level is one of the following:
    switch (protectionLevel) {
      case EXTERNAL:
      case EXTERNAL_VPC:
        return true;
      default:
        break;
    }

    return false;
  }

  /** Finds out and returns the proper DigestCase for the given algorithm. */
  Digest computeDigest(byte[] data, CryptoKeyVersion.CryptoKeyVersionAlgorithm algorithm)
      throws GeneralSecurityException {
    MessageDigest messageDigest;
    Digest.Builder digestBuilder = Digest.newBuilder();
    try {
      switch (algorithm) {
        case EC_SIGN_P256_SHA256:
        case EC_SIGN_SECP256K1_SHA256:
        case RSA_SIGN_PSS_2048_SHA256:
        case RSA_SIGN_PSS_3072_SHA256:
        case RSA_SIGN_PSS_4096_SHA256:
        case RSA_SIGN_PKCS1_2048_SHA256:
        case RSA_SIGN_PKCS1_3072_SHA256:
        case RSA_SIGN_PKCS1_4096_SHA256:
          messageDigest = MessageDigest.getInstance("SHA-256");
          digestBuilder.setSha256(ByteString.copyFrom(messageDigest.digest(data)));
          break;
        case EC_SIGN_P384_SHA384:
          messageDigest = MessageDigest.getInstance("SHA-384");
          digestBuilder.setSha384(ByteString.copyFrom(messageDigest.digest(data)));
          break;
        case RSA_SIGN_PSS_4096_SHA512:
        case RSA_SIGN_PKCS1_4096_SHA512:
          messageDigest = MessageDigest.getInstance("SHA-512");
          digestBuilder.setSha512(ByteString.copyFrom(messageDigest.digest(data)));
          break;
        default:
          throw new GeneralSecurityException("The given algorithm does not support digests.");
      }
    } catch (NoSuchAlgorithmException e) {
      throw new GeneralSecurityException(e);
    }

    return digestBuilder.build();
  }

  /** A Builder to create a {@link PublicKeySign} that communicates with Cloud KMS via gRPC. */
  public static final class Builder {
    @Nullable private String keyName = null;
    @Nullable private KeyManagementServiceClient kmsClient = null;
    private static final String KEY_NAME_PATTERN =
        "projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+/cryptoKeyVersions/.*";
    private static final Pattern KEY_NAME_MATCHER = Pattern.compile(KEY_NAME_PATTERN);

    private Builder() {}

    /** Set the ResourceName of the KMS key. */
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

    public PublicKeySign build() throws GeneralSecurityException {
      if (keyName == null) {
        throw new GeneralSecurityException("The keyName is null.");
      }

      if (!KEY_NAME_MATCHER.matcher(keyName).matches()) {
        throw new GeneralSecurityException("The keyName must follow " + KEY_NAME_PATTERN);
      }

      if (kmsClient == null) {
        throw new GeneralSecurityException("The KeyManagementServiceClient object is null.");
      }

      // Retrieve the related public key from KMS, that contains information on
      // how to prepare the later AsymmetricSign requests.
      try {
        GetPublicKeyRequest request = GetPublicKeyRequest.newBuilder().setName(keyName).build();
        PublicKey publicKey = kmsClient.getPublicKey(request);
        return new GcpKmsPublicKeySign(kmsClient, keyName, publicKey);
      } catch (RuntimeException e) {
        throw new GeneralSecurityException("The KMS GetPublicKey failed.", e);
      }
    }
  }

  public static Builder builder() {
    return new Builder();
  }
}
