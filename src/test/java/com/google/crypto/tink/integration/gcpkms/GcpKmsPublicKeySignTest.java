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
import com.google.cloud.kms.v1.ChecksummedData;
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
import io.grpc.Status;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import io.grpc.stub.StreamObserver;
import io.grpc.testing.GrpcCleanupRule;
import java.lang.reflect.Method;
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
  private static final String KEY_NAME_FOR_REQUEST_DIGEST_CRC32C =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions/9";
  private static final String KEY_NAME_FOR_GET_PUBLIC_KEY_EXCEPTION =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions/10";
  private static final String KEY_NAME_FOR_PUBLIC_KEY_CHECKSUM_MISMATCH =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions/11";
  private static final String KEY_NAME_FOR_ML_DSA_44 =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions/12";
  private static final String KEY_NAME_FOR_ML_DSA_65 =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions/13";
  private static final String KEY_NAME_FOR_ML_DSA_87 =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions/14";
  private static final String KEY_NAME_FOR_SLH_DSA =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions/15";
  private static final String KEY_NAME_FOR_HASH_SLH_DSA =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions/16";
  // The raw public key bytes and their CRC32C checksum returned by the fake KMS in the GetPublicKey
  // response.
  private static final ByteString PUBLIC_KEY_DATA = ByteString.copyFromUtf8("public key data");
  private static final Int64Value PUBLIC_KEY_CRC32C =
      Int64Value.of(Hashing.crc32c().hashBytes(PUBLIC_KEY_DATA.asReadOnlyByteBuffer()).padToLong());
  private static final byte[] dataForSign = "data for signing".getBytes(UTF_8);
  // The value of digest_crc32c for dataForSign
  private static final Int64Value REQUEST_DIGEST_CRC32C = Int64Value.of(62061691L);

  private PublicKeySign dataSigner;
  private PublicKeySign digestSigner;
  private PublicKeyVerify dataVerifier;
  private PublicKeyVerify digestVerifier;

  // The last AsymmetricSignRequest received by the fake KMS, used to assert on the request shape.
  private AsymmetricSignRequest capturedSignRequest;

  /** This rule manages automatic graceful shutdown for the registered servers and channels. */
  @Rule public final GrpcCleanupRule grpcCleanup = new GrpcCleanupRule();

  private KeyManagementServiceClient kmsClient;

  // Implement a fake KeyManagementService.
  public class FakeKmsImpl extends KeyManagementServiceImplBase {
    @Override
    public void asymmetricSign(
        AsymmetricSignRequest request, StreamObserver<AsymmetricSignResponse> responseObserver) {
      capturedSignRequest = request;
      AsymmetricSignResponse.Builder builder =
          AsymmetricSignResponse.newBuilder().setName(request.getName());
      try {
        byte[] signature = dataSigner.sign(request.getData().toByteArray());
        long signatureCrc32c = Hashing.crc32c().hashBytes(signature).padToLong();
        switch (request.getName()) {
          case KEY_NAME_FOR_DATA:
          case KEY_NAME_FOR_EXTERNAL_KEY:
          case KEY_NAME_FOR_ML_DSA_44:
          case KEY_NAME_FOR_ML_DSA_65:
          case KEY_NAME_FOR_ML_DSA_87:
          case KEY_NAME_FOR_SLH_DSA:
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
          case KEY_NAME_FOR_HASH_SLH_DSA:
            {
              signature = digestSigner.sign(request.getDigest().getSha256().toByteArray());
              signatureCrc32c = Hashing.crc32c().hashBytes(signature).padToLong();
              builder
                  .setVerifiedDigestCrc32C(true)
                  .setSignature(ByteString.copyFrom(signature))
                  .setSignatureCrc32C(Int64Value.of(signatureCrc32c));
              break;
            }
          case KEY_NAME_FOR_REQUEST_DIGEST_CRC32C:
            {
              // Checks the value of digest_crc32 in request is correct.
              if (!request.getDigestCrc32C().equals(REQUEST_DIGEST_CRC32C)) {
                throw new GeneralSecurityException("digest_crc32 is incorrect");
              }
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
      // SLH-DSA keys do not support PEM; KMS only returns them in NIST_PQC format.
      boolean isSlhDsa =
          request.getName().equals(KEY_NAME_FOR_SLH_DSA)
              || request.getName().equals(KEY_NAME_FOR_HASH_SLH_DSA);
      if (isSlhDsa && request.getPublicKeyFormat() != PublicKey.PublicKeyFormat.NIST_PQC) {
        responseObserver.onError(
            Status.INVALID_ARGUMENT
                .withDescription("Only NIST_PQC format is supported for SLH-DSA.")
                .asRuntimeException());
        return;
      }
      boolean isPqc =
          isSlhDsa
              || request.getName().equals(KEY_NAME_FOR_ML_DSA_44)
              || request.getName().equals(KEY_NAME_FOR_ML_DSA_65)
              || request.getName().equals(KEY_NAME_FOR_ML_DSA_87);
      if (!isPqc && request.getPublicKeyFormat() == PublicKey.PublicKeyFormat.NIST_PQC) {
        responseObserver.onError(
            Status.INVALID_ARGUMENT
                .withDescription("NIST_PQC format is not supported for this algorithm.")
                .asRuntimeException());
        return;
      }
      PublicKey.Builder builder =
          PublicKey.newBuilder()
              .setName(request.getName())
              .setPublicKeyFormat(request.getPublicKeyFormat())
              .setPublicKey(
                  ChecksummedData.newBuilder()
                      .setData(PUBLIC_KEY_DATA)
                      .setCrc32CChecksum(PUBLIC_KEY_CRC32C));
      switch (request.getName()) {
        case KEY_NAME_FOR_GET_PUBLIC_KEY_EXCEPTION:
          responseObserver.onError(new GeneralSecurityException("testing GetPublicKey exception."));
          return;
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
        case KEY_NAME_FOR_REQUEST_DIGEST_CRC32C:
          builder
              .setProtectionLevel(ProtectionLevel.SOFTWARE)
              .setAlgorithm(CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_P256_SHA256);
          break;
        case KEY_NAME_FOR_INVALID_ALGORITHM:
          builder
              .setProtectionLevel(ProtectionLevel.SOFTWARE)
              .setAlgorithm(CryptoKeyVersion.CryptoKeyVersionAlgorithm.HMAC_SHA256);
          break;
        case KEY_NAME_FOR_ML_DSA_44:
          builder
              .setProtectionLevel(ProtectionLevel.SOFTWARE)
              .setAlgorithm(CryptoKeyVersion.CryptoKeyVersionAlgorithm.PQ_SIGN_ML_DSA_44);
          break;
        case KEY_NAME_FOR_ML_DSA_65:
          builder
              .setProtectionLevel(ProtectionLevel.SOFTWARE)
              .setAlgorithm(CryptoKeyVersion.CryptoKeyVersionAlgorithm.PQ_SIGN_ML_DSA_65);
          break;
        case KEY_NAME_FOR_ML_DSA_87:
          builder
              .setProtectionLevel(ProtectionLevel.SOFTWARE)
              .setAlgorithm(CryptoKeyVersion.CryptoKeyVersionAlgorithm.PQ_SIGN_ML_DSA_87);
          break;
        case KEY_NAME_FOR_SLH_DSA:
          builder
              .setProtectionLevel(ProtectionLevel.SOFTWARE)
              .setAlgorithm(CryptoKeyVersion.CryptoKeyVersionAlgorithm.PQ_SIGN_SLH_DSA_SHA2_128S);
          break;
        case KEY_NAME_FOR_HASH_SLH_DSA:
          builder
              .setProtectionLevel(ProtectionLevel.SOFTWARE)
              .setAlgorithm(
                  CryptoKeyVersion.CryptoKeyVersionAlgorithm.PQ_SIGN_HASH_SLH_DSA_SHA2_128S_SHA256);
          break;
        case KEY_NAME_FOR_PUBLIC_KEY_CHECKSUM_MISMATCH:
          builder
              .setProtectionLevel(ProtectionLevel.SOFTWARE)
              .setAlgorithm(CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_ED25519)
              // Corrupt the checksum so it no longer matches the public key.
              .setPublicKey(
                  ChecksummedData.newBuilder()
                      .setData(PUBLIC_KEY_DATA)
                      .setCrc32CChecksum(Int64Value.of(PUBLIC_KEY_CRC32C.getValue() + 1)));
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
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () ->
                GcpKmsPublicKeySign.builder()
                    .setKeyName(KEY_NAME_WRONG_FORMAT)
                    .setKeyManagementServiceClient(kmsClient)
                    .build());
    assertThat(e).hasMessageThat().contains("The keyName must follow");
  }

  @Test
  public void kmsClientNotGiven() throws Exception {
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> GcpKmsPublicKeySign.builder().setKeyName(KEY_NAME_FOR_DATA).build());
    assertThat(e).hasMessageThat().contains("The KeyManagementServiceClient object is null");
  }

  @Test
  public void crc32cNotVerified() throws Exception {
    PublicKeySign kmsSigner =
        GcpKmsPublicKeySign.builder()
            .setKeyName(KEY_NAME_FOR_NO_VERIFIED_CRC32C)
            .setKeyManagementServiceClient(kmsClient)
            .build();
    GeneralSecurityException e =
        assertThrows(GeneralSecurityException.class, () -> kmsSigner.sign(dataForSign));
    assertThat(e).hasMessageThat().contains("Checking the input checksum failed");
  }

  @Test
  public void signatureCrc32cDoesNotMatch() throws Exception {
    PublicKeySign kmsSigner =
        GcpKmsPublicKeySign.builder()
            .setKeyName(KEY_NAME_FOR_SIGNATURE_MISMATCH)
            .setKeyManagementServiceClient(kmsClient)
            .build();
    GeneralSecurityException e =
        assertThrows(GeneralSecurityException.class, () -> kmsSigner.sign(dataForSign));
    assertThat(e).hasMessageThat().contains("Signature checksum mismatch");
  }

  @Test
  public void keyNameDoesNotMatch() throws Exception {
    PublicKeySign kmsSigner =
        GcpKmsPublicKeySign.builder()
            .setKeyName(KEY_NAME_FOR_KEY_NAME_MISMATCH)
            .setKeyManagementServiceClient(kmsClient)
            .build();
    GeneralSecurityException e =
        assertThrows(GeneralSecurityException.class, () -> kmsSigner.sign(dataForSign));
    assertThat(e).hasMessageThat().contains("The key name in the response does not match");
  }

  @Test
  public void asymmetricSignThrowsException() throws Exception {
    PublicKeySign kmsSigner =
        GcpKmsPublicKeySign.builder()
            .setKeyName(KEY_NAME_FOR_EXCEPTION)
            .setKeyManagementServiceClient(kmsClient)
            .build();
    GeneralSecurityException e =
        assertThrows(GeneralSecurityException.class, () -> kmsSigner.sign(dataForSign));
    assertThat(e).hasMessageThat().contains("Asymmetric sign failed");
  }

  @Test
  public void buildFailsForUnsupportedAlgorithm() throws Exception {
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () ->
                GcpKmsPublicKeySign.builder()
                    .setKeyName(KEY_NAME_FOR_INVALID_ALGORITHM)
                    .setKeyManagementServiceClient(kmsClient)
                    .build());
    assertThat(e).hasMessageThat().contains("is not supported");
  }

  @Test
  public void buildFailsWhenGetPublicKeyThrows() throws Exception {
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () ->
                GcpKmsPublicKeySign.builder()
                    .setKeyName(KEY_NAME_FOR_GET_PUBLIC_KEY_EXCEPTION)
                    .setKeyManagementServiceClient(kmsClient)
                    .build());
    assertThat(e).hasMessageThat().contains("The KMS GetPublicKey failed");
  }

  @Test
  public void buildFailsForPublicKeyChecksumMismatch() throws Exception {
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () ->
                GcpKmsPublicKeySign.builder()
                    .setKeyName(KEY_NAME_FOR_PUBLIC_KEY_CHECKSUM_MISMATCH)
                    .setKeyManagementServiceClient(kmsClient)
                    .build());
    assertThat(e).hasMessageThat().contains("The GetPublicKey checksum does not match");
  }

  @Test
  public void signFailsForTooLargeData() throws Exception {
    PublicKeySign kmsSigner =
        GcpKmsPublicKeySign.builder()
            .setKeyName(KEY_NAME_FOR_DATA)
            .setKeyManagementServiceClient(kmsClient)
            .build();

    byte[] tooLargeData = new byte[64 * 1024 + 1];
    GeneralSecurityException e =
        assertThrows(GeneralSecurityException.class, () -> kmsSigner.sign(tooLargeData));
    assertThat(e).hasMessageThat().contains("is larger than the allowed limit");
  }

  @Test
  public void signLargeDataSucceedsForDigestBasedAlgorithm() throws Exception {
    PublicKeySign kmsSigner =
        GcpKmsPublicKeySign.builder()
            .setKeyName(KEY_NAME_FOR_DIGEST)
            .setKeyManagementServiceClient(kmsClient)
            .build();

    byte[] tooLargeData = new byte[64 * 1024 + 1];
    byte[] kmsSignature = kmsSigner.sign(tooLargeData);
    MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
    Digest.Builder digestBuilder = Digest.newBuilder();
    byte[] digest =
        digestBuilder
            .setSha256(ByteString.copyFrom(messageDigest.digest(tooLargeData)))
            .build()
            .getSha256()
            .toByteArray();
    digestVerifier.verify(kmsSignature, digest);
  }

  @Test
  public void asymmetricSignWorksForDataExternalKey() throws Exception {
    PublicKeySign kmsSigner =
        GcpKmsPublicKeySign.builder()
            .setKeyName(KEY_NAME_FOR_EXTERNAL_KEY)
            .setKeyManagementServiceClient(kmsClient)
            .build();

    byte[] signature = dataSigner.sign(dataForSign);
    byte[] kmsSignature = kmsSigner.sign(dataForSign);
    dataVerifier.verify(kmsSignature, dataForSign);
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

  // Post-quantum data-mode algorithms (ML-DSA, SLH-DSA) forward the raw data to KMS, not a digest.
  private void assertDataModeSigningWorks(String keyName) throws Exception {
    PublicKeySign kmsSigner =
        GcpKmsPublicKeySign.builder()
            .setKeyName(keyName)
            .setKeyManagementServiceClient(kmsClient)
            .build();

    byte[] signature = dataSigner.sign(dataForSign);
    byte[] kmsSignature = kmsSigner.sign(dataForSign);
    dataVerifier.verify(kmsSignature, dataForSign);
    // We create deterministic signatures, check for equality.
    assertThat(kmsSignature).isEqualTo(signature);
    // The request must carry the data, not a digest.
    assertThat(capturedSignRequest.getData().toByteArray()).isEqualTo(dataForSign);
    assertThat(capturedSignRequest.hasDigest()).isFalse();
  }

  @Test
  public void asymmetricSignWorksForPqcAlgorithms() throws Exception {
    assertDataModeSigningWorks(KEY_NAME_FOR_ML_DSA_44);
    assertDataModeSigningWorks(KEY_NAME_FOR_ML_DSA_65);
    assertDataModeSigningWorks(KEY_NAME_FOR_ML_DSA_87);
    assertDataModeSigningWorks(KEY_NAME_FOR_SLH_DSA);
  }

  @Test
  public void asymmetricSignWorksForHashSlhDsa() throws Exception {
    PublicKeySign kmsSigner =
        GcpKmsPublicKeySign.builder()
            .setKeyName(KEY_NAME_FOR_HASH_SLH_DSA)
            .setKeyManagementServiceClient(kmsClient)
            .build();

    byte[] kmsSignature = kmsSigner.sign(dataForSign);
    byte[] expectedDigest = MessageDigest.getInstance("SHA-256").digest(dataForSign);
    digestVerifier.verify(kmsSignature, expectedDigest);

    assertThat(capturedSignRequest.getData().isEmpty()).isTrue();
    assertThat(capturedSignRequest.hasDigest()).isTrue();
    assertThat(capturedSignRequest.getDigest().getSha256().toByteArray()).isEqualTo(expectedDigest);
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

  @Test
  public void asymmetricSignHasCorrectDigestCrc32c() throws Exception {
    PublicKeySign kmsSigner =
        GcpKmsPublicKeySign.builder()
            .setKeyName(KEY_NAME_FOR_REQUEST_DIGEST_CRC32C)
            .setKeyManagementServiceClient(kmsClient)
            .build();

    byte[] kmsSignature = kmsSigner.sign(dataForSign);
    MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
    Digest.Builder digestBuilder = Digest.newBuilder();
    byte[] digest =
        digestBuilder
            .setSha256(ByteString.copyFrom(messageDigest.digest(dataForSign)))
            .build()
            .getSha256()
            .toByteArray();
    digestVerifier.verify(kmsSignature, digest);
  }

  @Test
  public void getDigestBytes_externalMu() throws Exception {
    Method getDigestBytesMethod =
        GcpKmsPublicKeySign.class.getDeclaredMethod("getDigestBytes", Digest.class);
    getDigestBytesMethod.setAccessible(true);

    ByteString muBytes = ByteString.copyFromUtf8("external_mu_bytes");
    Digest digest = Digest.newBuilder().setExternalMu(muBytes).build();
    ByteString result = (ByteString) getDigestBytesMethod.invoke(null, digest);
    assertThat(result).isEqualTo(muBytes);
  }

  @Test
  public void asymmetricSignDataRequestIsCorrect() throws Exception {
    PublicKeySign kmsSigner =
        GcpKmsPublicKeySign.builder()
            .setKeyName(KEY_NAME_FOR_DATA)
            .setKeyManagementServiceClient(kmsClient)
            .build();

    byte[] unused = kmsSigner.sign(dataForSign);

    // Data-mode algorithms sign the raw data: the request must carry the data (with its checksum)
    // and no digest.
    assertThat(capturedSignRequest.getName()).isEqualTo(KEY_NAME_FOR_DATA);
    assertThat(capturedSignRequest.getData().toByteArray()).isEqualTo(dataForSign);
    assertThat(capturedSignRequest.hasDataCrc32C()).isTrue();
    assertThat(capturedSignRequest.getDataCrc32C().getValue())
        .isEqualTo(Hashing.crc32c().hashBytes(dataForSign).padToLong());
    assertThat(capturedSignRequest.hasDigest()).isFalse();
    assertThat(capturedSignRequest.hasDigestCrc32C()).isFalse();
  }

  @Test
  public void asymmetricSignDigestRequestIsCorrect() throws Exception {
    PublicKeySign kmsSigner =
        GcpKmsPublicKeySign.builder()
            .setKeyName(KEY_NAME_FOR_DIGEST)
            .setKeyManagementServiceClient(kmsClient)
            .build();

    byte[] unused = kmsSigner.sign(dataForSign);

    // Digest-mode algorithms sign a digest of the data: the request must carry the correct SHA-256
    // digest (with its checksum) and no data.
    byte[] expectedDigest = MessageDigest.getInstance("SHA-256").digest(dataForSign);
    assertThat(capturedSignRequest.getName()).isEqualTo(KEY_NAME_FOR_DIGEST);
    assertThat(capturedSignRequest.getData().isEmpty()).isTrue();
    assertThat(capturedSignRequest.hasDataCrc32C()).isFalse();
    assertThat(capturedSignRequest.hasDigest()).isTrue();
    assertThat(capturedSignRequest.getDigest().getSha256().toByteArray()).isEqualTo(expectedDigest);
    assertThat(capturedSignRequest.hasDigestCrc32C()).isTrue();
    assertThat(capturedSignRequest.getDigestCrc32C().getValue())
        .isEqualTo(Hashing.crc32c().hashBytes(expectedDigest).padToLong());
  }
}
