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
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PemKeyType;
import com.google.crypto.tink.signature.SignaturePemKeysetReader;
import com.google.crypto.tink.signature.internal.EcdsaProtoSerialization;
import com.google.crypto.tink.signature.internal.Ed25519ProtoSerialization;
import com.google.crypto.tink.signature.internal.MlDsaProtoSerialization;
import com.google.crypto.tink.signature.internal.RsaSsaPkcs1ProtoSerialization;
import com.google.crypto.tink.signature.internal.RsaSsaPssProtoSerialization;
import java.security.GeneralSecurityException;
import java.util.List;

/** Imports Cloud KMS {@code FetchVerificationKeys} public keys into a Tink {@link KeysetHandle}. */
public final class GcpKmsVerificationKeys {

  /** A public key returned by Cloud KMS {@code FetchVerificationKeys}. */
  public static final class VerificationKey {
    private final String publicKeyPem;
    private final CryptoKeyVersion.CryptoKeyVersionAlgorithm algorithm;

    private VerificationKey(
        String publicKeyPem, CryptoKeyVersion.CryptoKeyVersionAlgorithm algorithm) {
      this.publicKeyPem = publicKeyPem;
      this.algorithm = algorithm;
    }

    public static VerificationKey create(
        String publicKeyPem, CryptoKeyVersion.CryptoKeyVersionAlgorithm algorithm) {
      return new VerificationKey(publicKeyPem, algorithm);
    }

    public String getPublicKeyPem() {
      return publicKeyPem;
    }

    public CryptoKeyVersion.CryptoKeyVersionAlgorithm getAlgorithm() {
      return algorithm;
    }
  }

  /**
   * Creates a public {@link KeysetHandle} from the (PEM, algorithm) pairs returned by Cloud KMS
   * {@code FetchVerificationKeys}, without calling KMS. Keys are imported with no output prefix and
   * DER signature encoding for ECDSA; the first key is the primary. Callers unpacking {@code
   * FetchVerificationKeysResponse} should paginate {@code next_page_token}, verify each key's
   * {@code crc32c_checksum}, and order {@code keys} newest-first so the newest version is primary.
   *
   * <p>Accepts the algorithms of {@link GcpKmsPublicKeyVerify} (plus {@code EC_SIGN_ED25519})
   * except SLH-DSA. Any unsupported or invalid key throws an exception, so callers migrating off an
   * unsupported algorithm must filter those versions out first.
   *
   * <p><b>Warning:</b> This API is in preview and may change in the future.
   */
  public static KeysetHandle toPublicKeysetHandle(List<VerificationKey> keys)
      throws GeneralSecurityException {
    if (keys.isEmpty()) {
      throw new GeneralSecurityException("No verification keys given.");
    }
    EcdsaProtoSerialization.register();
    Ed25519ProtoSerialization.register();
    RsaSsaPkcs1ProtoSerialization.register();
    RsaSsaPssProtoSerialization.register();
    MlDsaProtoSerialization.register();
    KeysetHandle.Builder builder = KeysetHandle.newBuilder();
    for (int i = 0; i < keys.size(); i++) {
      KeysetHandle.Builder.Entry entry =
          KeysetHandle.importKey(parsePublicKey(keys.get(i))).withRandomId();
      if (i == 0) {
        entry.makePrimary();
      }
      builder.addEntry(entry);
    }
    return builder.build();
  }

  private static Key parsePublicKey(VerificationKey key) throws GeneralSecurityException {
    PemKeyType pemKeyType = pemKeyType(key.getAlgorithm());
    KeysetHandle parsed;
    try {
      parsed =
          SignaturePemKeysetReader.newBuilder()
              .addPem(key.getPublicKeyPem(), pemKeyType)
              .buildPublicKeysetHandle();
    } catch (GeneralSecurityException e) {
      throw new GeneralSecurityException(
          "Cannot parse the public key for algorithm " + key.getAlgorithm() + ".", e);
    }
    if (parsed.size() != 1) {
      throw new GeneralSecurityException(
          "Expected one public key in the PEM for algorithm "
              + key.getAlgorithm()
              + ", found "
              + parsed.size()
              + ".");
    }
    return parsed.getPrimary().getKey();
  }

  @SuppressWarnings("StatementSwitchToExpressionSwitch")
  private static PemKeyType pemKeyType(CryptoKeyVersion.CryptoKeyVersionAlgorithm algorithm)
      throws GeneralSecurityException {
    switch (algorithm) {
      case EC_SIGN_P256_SHA256:
        return PemKeyType.ECDSA_P256_SHA256;
      case EC_SIGN_P384_SHA384:
        return PemKeyType.ECDSA_P384_SHA384;
      case EC_SIGN_ED25519:
        return PemKeyType.ED25519;
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

  private GcpKmsVerificationKeys() {}
}
