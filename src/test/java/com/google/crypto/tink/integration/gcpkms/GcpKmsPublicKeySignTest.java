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

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.api.gax.core.NoCredentialsProvider;
import com.google.api.gax.grpc.GrpcTransportChannel;
import com.google.api.gax.rpc.FixedTransportChannelProvider;
import com.google.cloud.kms.v1.AsymmetricSignRequest;
import com.google.cloud.kms.v1.AsymmetricSignResponse;
import com.google.cloud.kms.v1.CryptoKeyVersion;
import com.google.cloud.kms.v1.Digest;
import com.google.cloud.kms.v1.GetPublicKeyRequest;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.KeyManagementServiceGrpc.KeyManagementServiceImplBase;
import com.google.cloud.kms.v1.KeyManagementServiceSettings;
import com.google.cloud.kms.v1.ProtectionLevel;
import com.google.cloud.kms.v1.PublicKey;
import com.google.common.hash.Hashing;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.signature.PredefinedSignatureParameters;
import com.google.crypto.tink.signature.SignatureConfig;
import com.google.protobuf.ByteString;
import com.google.protobuf.Int64Value;
import io.grpc.ManagedChannel;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import io.grpc.stub.StreamObserver;
import io.grpc.testing.GrpcCleanupRule;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class GcpKmsPublicKeySignTest {
  private static final String KEY_NAME_WRONG_FORMAT =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions";
  private static final String KEY_NAME_FOR_DATA =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions/1";
  private static final String KEY_NAME_FOR_DIGEST =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions/2";
  private static final String KEY_NAME_FOR_NO_VERIFIED_CRC32C =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions/3";
  private static final String KEY_NAME_FOR_SIGNATURE_MISMATCH =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions/4";
  private static final String KEY_NAME_FOR_KEY_NAME_MISMATCH =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions/5";
  private static final String KEY_NAME_FOR_EXCEPTION =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions/6";
  private static final String KEY_NAME_FOR_EXTERNAL_KEY =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions/7";
  private static final String KEY_NAME_FOR_INVALID_ALGORITHM =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions/8";
  private static final String KEY_PEM = "PEM";
  private static final byte[] DATA_FOR_SIGN = "data for signing".getBytes(UTF_8);

  private PublicKeySign dataSigner;
  private PublicKeySign digestSigner;
  private PublicKeyVerify dataVerifier;
  private PublicKeyVerify digestVerifier;

  /** This rule manages automatic graceful shutdown for the registered servers and channels. */
  @Rule public final GrpcCleanupRule grpcCleanup = new GrpcCleanupRule();

  private KeyManagementServiceClient kmsClient;

  // Implement a fake KeyManagementService.
  public class FakeKmsImpl extends KeyManagementServiceImplBase {
    @Override
    public void asymmetricSign(
        AsymmetricSignRequest request, StreamObserver<AsymmetricSignResponse> responseObserver) {
      AsymmetricSignResponse.Builder builder =
          AsymmetricSignResponse.newBuilder().setName(request.getName());
      try {
        byte[] signature = dataSigner.sign(request.getData().toByteArray());
        long signatureCrc32c = Hashing.crc32c().hashBytes(signature).padToLong();
        switch (request.getName()) {
          case KEY_NAME_FOR_DATA:
          case KEY_NAME_FOR_EXTERNAL_KEY:
            {
              builder
                  .setVerifiedDataCrc32C(true)
                  .setSignature(ByteString.copyFrom(signature))
                  .setSignatureCrc32C(Int64Value.of(signatureCrc32c));
              break;
            }
          case KEY_NAME_FOR_NO_VERIFIED_CRC32C:
            {
              builder
                  .setSignature(ByteString.copyFrom(signature))
                  .setSignatureCrc32C(Int64Value.of(signatureCrc32c));
              break;
            }
          case KEY_NAME_FOR_SIGNATURE_MISMATCH:
            {
              builder
                  .setVerifiedDataCrc32C(true)
                  .setSignature(ByteString.copyFrom(signature))
                  // Manipulate the signature crc32c.
                  .setSignatureCrc32C(Int64Value.of(signatureCrc32c + 1));
              break;
            }
          case KEY_NAME_FOR_KEY_NAME_MISMATCH:
            {
              builder
                  // Set a wrong keyName.
                  .setName(KEY_NAME_FOR_DIGEST)
                  .setVerifiedDataCrc32C(true)
                  .setSignature(ByteString.copyFrom(signature))
                  .setSignatureCrc32C(Int64Value.of(signatureCrc32c));
              break;
            }
          case KEY_NAME_FOR_DIGEST:
            {
              signature = digestSigner.sign(request.getDigest().getSha256().toByteArray());
              signatureCrc32c = Hashing.crc32c().hashBytes(signature).padToLong();
              builder
                  .setVerifiedDigestCrc32C(true)
                  .setSignature(ByteString.copyFrom(signature))
                  .setSignatureCrc32C(Int64Value.of(signatureCrc32c));
              break;
            }
          case KEY_NAME_FOR_EXCEPTION:
            throw new GeneralSecurityException("testing exception.");
          default:
            return;
        }

        responseObserver.onNext(builder.build());
        responseObserver.onCompleted();
      } catch (GeneralSecurityException e) {
        responseObserver.onError(e);
      }
    }

    @Override
    public void getPublicKey(
        GetPublicKeyRequest request, StreamObserver<PublicKey> responseObserver) {
      PublicKey.Builder builder = PublicKey.newBuilder().setName(request.getName()).setPem(KEY_PEM);
      switch (request.getName()) {
        case KEY_NAME_FOR_DATA:
        case KEY_NAME_FOR_NO_VERIFIED_CRC32C:
        case KEY_NAME_FOR_SIGNATURE_MISMATCH:
        case KEY_NAME_FOR_KEY_NAME_MISMATCH:
        case KEY_NAME_FOR_EXCEPTION:
          builder
              .setProtectionLevel(ProtectionLevel.SOFTWARE)
              .setAlgorithm(CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_ED25519);
          break;
        case KEY_NAME_FOR_EXTERNAL_KEY:
          builder
              .setProtectionLevel(ProtectionLevel.EXTERNAL)
              .setAlgorithm(CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_2048_SHA256);
          break;
        case KEY_NAME_FOR_DIGEST:
          builder
              .setProtectionLevel(ProtectionLevel.SOFTWARE)
              .setAlgorithm(CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_P256_SHA256);
          break;
        case KEY_NAME_FOR_INVALID_ALGORITHM:
          builder
              .setProtectionLevel(ProtectionLevel.SOFTWARE)
              .setAlgorithm(CryptoKeyVersion.CryptoKeyVersionAlgorithm.HMAC_SHA256);
          break;
        default:
          break;
      }
      responseObserver.onNext(builder.build());
      responseObserver.onCompleted();
    }
  }

  @Before
  public void setUpClass() throws Exception {
    try {
      SignatureConfig.register();
      KeysetHandle keysetHandleData =
          KeysetHandle.generateNew(PredefinedSignatureParameters.ED25519);
      dataSigner = keysetHandleData.getPrimitive(RegistryConfiguration.get(), PublicKeySign.class);
      dataVerifier =
          keysetHandleData
              .getPublicKeysetHandle()
              .getPrimitive(RegistryConfiguration.get(), PublicKeyVerify.class);

      KeysetHandle keysetHandleDigest =
          KeysetHandle.generateNew(PredefinedSignatureParameters.ECDSA_P256);
      digestSigner =
          keysetHandleDigest.getPrimitive(RegistryConfiguration.get(), PublicKeySign.class);
      digestVerifier =
          keysetHandleDigest
              .getPublicKeysetHandle()
              .getPrimitive(RegistryConfiguration.get(), PublicKeyVerify.class);
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    }

    // Create a server, add service, start, and register for automatic graceful shutdown.
    String serverName = InProcessServerBuilder.generateName();
    grpcCleanup.register(
        InProcessServerBuilder.forName(serverName)
            .directExecutor()
            .addService(new FakeKmsImpl())
            .build()
            .start());

    // Create a client channel and register for automatic graceful shutdown.
    ManagedChannel channel =
        grpcCleanup.register(InProcessChannelBuilder.forName(serverName).directExecutor().build());
    KeyManagementServiceSettings kmsSettings =
        KeyManagementServiceSettings.newBuilder()
            .setCredentialsProvider(NoCredentialsProvider.create())
            .setTransportChannelProvider(
                FixedTransportChannelProvider.create(
                    GrpcTransportChannel.newBuilder().setManagedChannel(channel).build()))
            .build();
    kmsClient = KeyManagementServiceClient.create(kmsSettings);
  }

  @Test
  public void keyNameNotSet() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> GcpKmsPublicKeySign.builder().setKeyManagementServiceClient(kmsClient).build());
  }

  @Test
  public void keyNameIsEmpty() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            GcpKmsPublicKeySign.builder()
                .setKeyName("")
                .setKeyManagementServiceClient(kmsClient)
                .build());
  }

  @Test
  public void keyNameInWrongFormat() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            GcpKmsPublicKeySign.builder()
                .setKeyName(KEY_NAME_WRONG_FORMAT)
                .setKeyManagementServiceClient(kmsClient)
                .build());
  }

  @Test
  public void kmsClientNotGiven() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> GcpKmsPublicKeySign.builder().setKeyName(KEY_NAME_FOR_DATA).build());
  }

  @Test
  public void crc32cNotVerified() throws Exception {
    PublicKeySign kmsSigner =
        GcpKmsPublicKeySign.builder()
            .setKeyName(KEY_NAME_FOR_NO_VERIFIED_CRC32C)
            .setKeyManagementServiceClient(kmsClient)
            .build();
    assertThrows(GeneralSecurityException.class, () -> kmsSigner.sign(DATA_FOR_SIGN));
  }

  @Test
  public void signatureCrc32cDoesNotMatch() throws Exception {
    PublicKeySign kmsSigner =
        GcpKmsPublicKeySign.builder()
            .setKeyName(KEY_NAME_FOR_SIGNATURE_MISMATCH)
            .setKeyManagementServiceClient(kmsClient)
            .build();
    assertThrows(GeneralSecurityException.class, () -> kmsSigner.sign(DATA_FOR_SIGN));
  }

  @Test
  public void keyNameDoesNotMatch() throws Exception {
    PublicKeySign kmsSigner =
        GcpKmsPublicKeySign.builder()
            .setKeyName(KEY_NAME_FOR_KEY_NAME_MISMATCH)
            .setKeyManagementServiceClient(kmsClient)
            .build();
    assertThrows(GeneralSecurityException.class, () -> kmsSigner.sign(DATA_FOR_SIGN));
  }

  @Test
  public void asymmetricSignThrowsException() throws Exception {
    PublicKeySign kmsSigner =
        GcpKmsPublicKeySign.builder()
            .setKeyName(KEY_NAME_FOR_EXCEPTION)
            .setKeyManagementServiceClient(kmsClient)
            .build();
    assertThrows(GeneralSecurityException.class, () -> kmsSigner.sign(DATA_FOR_SIGN));
  }

  @Test
  public void asymmetricSignInvalidAlgorithm() throws Exception {
    PublicKeySign kmsSigner =
        GcpKmsPublicKeySign.builder()
            .setKeyName(KEY_NAME_FOR_INVALID_ALGORITHM)
            .setKeyManagementServiceClient(kmsClient)
            .build();
    assertThrows(GeneralSecurityException.class, () -> kmsSigner.sign(DATA_FOR_SIGN));
  }

  @Test
  public void asymmetricSignWorksForDataExternalKey() throws Exception {
    PublicKeySign kmsSigner =
        GcpKmsPublicKeySign.builder()
            .setKeyName(KEY_NAME_FOR_EXTERNAL_KEY)
            .setKeyManagementServiceClient(kmsClient)
            .build();

    byte[] signature = dataSigner.sign(DATA_FOR_SIGN);
    byte[] kmsSignature = kmsSigner.sign(DATA_FOR_SIGN);
    dataVerifier.verify(kmsSignature, DATA_FOR_SIGN);
    // ED25519 is deterministic, check that signatures are the same.
    assertThat(kmsSignature).isEqualTo(signature);
  }

  @Test
  public void asymmetricSignWorksForData() throws Exception {
    PublicKeySign kmsSigner =
        GcpKmsPublicKeySign.builder()
            .setKeyName(KEY_NAME_FOR_DATA)
            .setKeyManagementServiceClient(kmsClient)
            .build();

    byte[] data1 = "data1 for signing".getBytes(UTF_8);
    byte[] data2 = "data2 for signing".getBytes(UTF_8);
    byte[] signature1 = dataSigner.sign(data1);
    byte[] signature2 = dataSigner.sign(data2);
    byte[] kmsSignature1 = kmsSigner.sign(data1);
    byte[] kmsSignature2 = kmsSigner.sign(data2);
    // ED25519 is deterministic, check that signatures are the same.
    assertThat(kmsSignature1).isEqualTo(signature1);
    assertThat(kmsSignature2).isEqualTo(signature2);
    assertThat(kmsSignature1).isNotEqualTo(signature2);
    // Verify the signatures.
    dataVerifier.verify(kmsSignature1, data1);
    dataVerifier.verify(kmsSignature2, data2);
    assertThrows(GeneralSecurityException.class, () -> dataVerifier.verify(kmsSignature1, data2));
    assertThrows(GeneralSecurityException.class, () -> dataVerifier.verify(kmsSignature2, data1));
  }

  @Test
  public void asymmetricSignWorksForDigest() throws Exception {
    PublicKeySign kmsSigner =
        GcpKmsPublicKeySign.builder()
            .setKeyName(KEY_NAME_FOR_DIGEST)
            .setKeyManagementServiceClient(kmsClient)
            .build();

    byte[] data1 = "data1 for signing".getBytes(UTF_8);
    byte[] data2 = "data2 for signing".getBytes(UTF_8);
    byte[] kmsSignature1 = kmsSigner.sign(data1);
    byte[] kmsSignature2 = kmsSigner.sign(data2);
    MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
    Digest.Builder digestBuilder = Digest.newBuilder();
    byte[] digest1 =
        digestBuilder
            .setSha256(ByteString.copyFrom(messageDigest.digest(data1)))
            .build()
            .getSha256()
            .toByteArray();
    byte[] digest2 =
        digestBuilder
            .setSha256(ByteString.copyFrom(messageDigest.digest(data2)))
            .build()
            .getSha256()
            .toByteArray();

    // Verify the signatures.
    digestVerifier.verify(kmsSignature1, digest1);
    digestVerifier.verify(kmsSignature2, digest2);
    assertThrows(
        GeneralSecurityException.class, () -> digestVerifier.verify(kmsSignature1, digest2));
    assertThrows(
        GeneralSecurityException.class, () -> digestVerifier.verify(kmsSignature2, digest1));
  }
}
