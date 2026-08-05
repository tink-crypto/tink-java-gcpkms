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

import com.google.cloud.kms.v1.CryptoKeyVersion;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.PublicKey;
import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PemKeyType;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.integration.gcpkms.internal.GcpKmsUtil;
import com.google.crypto.tink.signature.SignatureConfig2026;
import com.google.crypto.tink.signature.SignaturePemKeysetReader;
import com.google.crypto.tink.signature.SlhDsaParameters;
import com.google.crypto.tink.signature.SlhDsaPublicKey;
import com.google.crypto.tink.signature.SlhDsaSignKeyManager;
import com.google.crypto.tink.signature.internal.EcdsaProtoSerialization;
import com.google.crypto.tink.signature.internal.RsaSsaPkcs1ProtoSerialization;
import com.google.crypto.tink.signature.internal.RsaSsaPssProtoSerialization;
import com.google.crypto.tink.util.Bytes;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/**
 * A {@link PublicKeyVerify} that verifies signatures using the public key of an asymmetric key in
 * <a href="https://cloud.google.com/kms/">Google Cloud KMS</a>.
 *
 * <p>The verifier is built upon the public key that's fetched from Cloud KMS once, and is used to
 * verify signatures locally. Cloud KMS is not contacted again. The public key can either be fetched
 * from Cloud KMS (by setting a {@code KeyManagementServiceClient} and key name) or supplied
 * directly by the caller (by setting a pre-fetched public key), which builds the verifier without
 * any RPCs.
 *
 * <p>Verifying post-quantum signatures (ML-DSA and SLH-DSA) requires a Conscrypt provider that
 * supports those algorithms to be installed, e.g. by calling {@code
 * Security.addProvider(Conscrypt.newProvider())}. Without it, {@link Builder#build} fails for
 * post-quantum keys.
 */
public final class GcpKmsPublicKeyVerify implements PublicKeyVerify {

  /** A local Tink verifier built from the public key fetched from Cloud KMS. */
  private final PublicKeyVerify verifier;

  private GcpKmsPublicKeyVerify(PublicKeyVerify verifier) {
    this.verifier = verifier;
  }

  @Override
  public void verify(final byte[] signature, final byte[] data) throws GeneralSecurityException {
    verifier.verify(signature, data);
  }

  /**
   * Returns the {@link PemKeyType} matching the Cloud KMS {@code algorithm}, or throws if the
   * algorithm is not supported for verification through Tink.
   */
  private static PemKeyType pemKeyType(CryptoKeyVersion.CryptoKeyVersionAlgorithm algorithm)
      throws GeneralSecurityException {
    switch (algorithm) {
      case EC_SIGN_P256_SHA256:
        return PemKeyType.ECDSA_P256_SHA256;
      case EC_SIGN_P384_SHA384:
        return PemKeyType.ECDSA_P384_SHA384;
      case RSA_SIGN_PKCS1_2048_SHA256:
        return PemKeyType.RSA_SIGN_PKCS1_2048_SHA256;
      case RSA_SIGN_PKCS1_3072_SHA256:
        return PemKeyType.RSA_SIGN_PKCS1_3072_SHA256;
      case RSA_SIGN_PKCS1_4096_SHA256:
        return PemKeyType.RSA_SIGN_PKCS1_4096_SHA256;
      case RSA_SIGN_PKCS1_4096_SHA512:
        return PemKeyType.RSA_SIGN_PKCS1_4096_SHA512;
      case RSA_SIGN_PSS_2048_SHA256:
        return PemKeyType.RSA_PSS_2048_SHA256;
      case RSA_SIGN_PSS_3072_SHA256:
        return PemKeyType.RSA_PSS_3072_SHA256;
      case RSA_SIGN_PSS_4096_SHA256:
        return PemKeyType.RSA_PSS_4096_SHA256;
      case RSA_SIGN_PSS_4096_SHA512:
        return PemKeyType.RSA_PSS_4096_SHA512;
      case PQ_SIGN_ML_DSA_44:
      case PQ_SIGN_ML_DSA_44_EXTERNAL_MU:
        return PemKeyType.ML_DSA_44;
      case PQ_SIGN_ML_DSA_65:
      case PQ_SIGN_ML_DSA_65_EXTERNAL_MU:
        return PemKeyType.ML_DSA_65;
      case PQ_SIGN_ML_DSA_87:
      case PQ_SIGN_ML_DSA_87_EXTERNAL_MU:
        return PemKeyType.ML_DSA_87;
      default:
        throw new GeneralSecurityException("The algorithm " + algorithm + " is not supported.");
    }
  }

  /**
   * Builds a single-key keyset handle from the raw NIST_PQC public key bytes returned by KMS.
   *
   * <p>Only SLH-DSA is served this way; the prehash SLH-DSA variant is not one of the algorithms
   * the PQC keyset builder supports, so it is rejected on this path.
   */
  @AccessesPartialKey
  private static KeysetHandle slhDsaKeysetHandle(
      CryptoKeyVersion.CryptoKeyVersionAlgorithm algorithm, ByteString publicKeyBytes)
      throws GeneralSecurityException {
    Bytes serializedPublicKey = Bytes.copyFrom(publicKeyBytes.toByteArray());
    Key publicKey;
    switch (algorithm) {
      case PQ_SIGN_SLH_DSA_SHA2_128S:
        SlhDsaSignKeyManager.registerPair();
        publicKey =
            SlhDsaPublicKey.builder()
                .setParameters(
                    SlhDsaParameters.createSlhDsaWithSha2And128S(
                        SlhDsaParameters.Variant.NO_PREFIX))
                .setSerializedPublicKey(serializedPublicKey)
                .build();
        break;
      default:
        throw new GeneralSecurityException("The algorithm " + algorithm + " is not supported.");
    }
    return KeysetHandle.newBuilder()
        .addEntry(KeysetHandle.importKey(publicKey).withRandomId().makePrimary())
        .build();
  }

  /**
   * Returns whether the given algorithm's public key is supplied as raw NIST_PQC key bytes
   * (SLH-DSA) rather than PEM.
   */
  private static boolean isSlhDsa(CryptoKeyVersion.CryptoKeyVersionAlgorithm algorithm) {
    switch (algorithm) {
      case PQ_SIGN_SLH_DSA_SHA2_128S:
      case PQ_SIGN_HASH_SLH_DSA_SHA2_128S_SHA256:
        return true;
      default:
        return false;
    }
  }

  /**
   * A Builder to create a {@link PublicKeyVerify} that uses a public key from Cloud KMS.
   *
   * <p>Set either a {@link #setKeyManagementServiceClient client} and {@link #setKeyName key name}
   * to fetch the public key from Cloud KMS, or a {@link #setPublicKey pre-fetched public key} and
   * {@link #setAlgorithm algorithm} to build the verifier without any RPCs; not both.
   */
  public static final class Builder {
    @Nullable private String keyName = null;
    @Nullable private KeyManagementServiceClient kmsClient = null;
    @Nullable private byte[] publicKey = null;
    @Nullable private CryptoKeyVersion.CryptoKeyVersionAlgorithm algorithm = null;

    private Builder() {}

    /**
     * Sets the ResourceName of the KMS key. Must be used together with {@link
     * #setKeyManagementServiceClient}. Incompatible with {@link #setPublicKey} and {@link
     * #setAlgorithm}.
     */
    @CanIgnoreReturnValue
    public Builder setKeyName(String keyName) {
      this.keyName = keyName;
      return this;
    }

    /**
     * Sets the {@link KeyManagementServiceClient} object. Must be used together with {@link
     * #setKeyName}. Incompatible with {@link #setPublicKey} and {@link #setAlgorithm}.
     */
    @CanIgnoreReturnValue
    public Builder setKeyManagementServiceClient(KeyManagementServiceClient kmsClient) {
      this.kmsClient = kmsClient;
      return this;
    }

    /**
     * Set a public key that was previously fetched from Cloud KMS, to build the verifier without
     * contacting Cloud KMS. Must be used together with {@link #setAlgorithm}.
     *
     * <p>{@code publicKey} must be the exact bytes returned by Cloud KMS {@code GetPublicKey} for
     * the algorithm. Note that the integrity of {@code publicKey} is the caller's responsibility.
     */
    @CanIgnoreReturnValue
    public Builder setPublicKey(byte[] publicKey) {
      this.publicKey = (publicKey != null) ? publicKey.clone() : null;
      return this;
    }

    /**
     * Set the {@code CryptoKeyVersion} algorithm of the pre-fetched public key. Must be used
     * together with {@link #setPublicKey}.
     */
    @CanIgnoreReturnValue
    public Builder setAlgorithm(CryptoKeyVersion.CryptoKeyVersionAlgorithm algorithm) {
      this.algorithm = algorithm;
      return this;
    }

    /** Builds a new {@link PublicKeyVerify} instance. */
    public PublicKeyVerify build() throws GeneralSecurityException {
      // Registers the necessary proto parsers for the supported signature key types.
      EcdsaProtoSerialization.register();
      RsaSsaPkcs1ProtoSerialization.register();
      RsaSsaPssProtoSerialization.register();

      // A verifier is either offline (caller-supplied public key) or online (key fetched from KMS).
      boolean isOffline = (publicKey != null || algorithm != null);
      boolean isOnline = (keyName != null || kmsClient != null);

      if (isOffline && isOnline) {
        throw new GeneralSecurityException(
            "Set either a pre-fetched public key or a KMS client and key name, not both.");
      }
      if (!isOffline && !isOnline) {
        throw new GeneralSecurityException(
            "Must set either a pre-fetched public key or a KMS client and key name.");
      }

      CryptoKeyVersion.CryptoKeyVersionAlgorithm algorithm;
      ByteString publicKeyData;
      if (isOffline) {
        if (this.publicKey == null) {
          throw new GeneralSecurityException("The pre-fetched public key is null.");
        }
        if (this.algorithm == null) {
          throw new GeneralSecurityException("The algorithm is null.");
        }
        algorithm = this.algorithm;
        publicKeyData = ByteString.copyFrom(publicKey);
      } else {
        GcpKmsUtil.validateKeyName(keyName);
        if (kmsClient == null) {
          throw new GeneralSecurityException("The KeyManagementServiceClient object is null.");
        }
        PublicKey fetchedKey = GcpKmsUtil.fetchPublicKey(kmsClient, keyName);
        algorithm = fetchedKey.getAlgorithm();
        publicKeyData = fetchedKey.getPublicKey().getData();
      }
      // Build a local Tink verifier, choosing the raw post-quantum or PEM representation as
      // required by the algorithm.
      KeysetHandle keysetHandle;
      if (isSlhDsa(algorithm)) {
        keysetHandle = slhDsaKeysetHandle(algorithm, publicKeyData);
      } else {
        keysetHandle =
            SignaturePemKeysetReader.newBuilder()
                .addPem(publicKeyData.toStringUtf8(), pemKeyType(algorithm))
                .buildPublicKeysetHandle();
      }
      return new GcpKmsPublicKeyVerify(
          keysetHandle.getPrimitive(SignatureConfig2026.get(), PublicKeyVerify.class));
    }
  }

  public static Builder builder() {
    return new Builder();
  }
}
