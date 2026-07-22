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
import static com.google.crypto.tink.integration.gcpkms.internal.GcpKmsUtil.checksummedData;
import static org.junit.Assert.assertThrows;

import com.google.api.gax.core.NoCredentialsProvider;
import com.google.api.gax.grpc.GrpcTransportChannel;
import com.google.api.gax.rpc.FixedTransportChannelProvider;
import com.google.cloud.kms.v1.ChecksummedData;
import com.google.cloud.kms.v1.CryptoKeyVersion.CryptoKeyVersionAlgorithm;
import com.google.cloud.kms.v1.GetPublicKeyRequest;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.KeyManagementServiceGrpc.KeyManagementServiceImplBase;
import com.google.cloud.kms.v1.KeyManagementServiceSettings;
import com.google.cloud.kms.v1.PublicKey;
import com.google.common.hash.Hashing;
import com.google.protobuf.ByteString;
import com.google.protobuf.Int64Value;
import io.grpc.ManagedChannel;
import io.grpc.Status;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import io.grpc.stub.StreamObserver;
import io.grpc.testing.GrpcCleanupRule;
import java.security.GeneralSecurityException;
import java.util.function.BiConsumer;
import org.junit.Before;
import org.junit.Rule;
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

  private static final ByteString PUBLIC_KEY_DATA = ByteString.copyFromUtf8("public key data");

  /** This rule manages automatic graceful shutdown for the registered servers and channels. */
  @Rule public final GrpcCleanupRule grpcCleanup = new GrpcCleanupRule();

  // A configurable fake KMS whose GetPublicKey behavior each test sets via setGetPublicKeyHandler.
  private final FakeKeyManagementService fakeKms = new FakeKeyManagementService();
  private KeyManagementServiceClient kmsClient;

  // A fake KeyManagementService that delegates GetPublicKey to an injectable handler, so each test
  // can drive a single branch of GcpKmsUtil.fetchPublicKey without a bespoke fake.
  private static final class FakeKeyManagementService extends KeyManagementServiceImplBase {
    private BiConsumer<GetPublicKeyRequest, StreamObserver<PublicKey>> getPublicKeyHandler =
        (request, responseObserver) ->
            responseObserver.onError(
                Status.UNIMPLEMENTED.withDescription("no handler set").asRuntimeException());

    void setGetPublicKeyHandler(
        BiConsumer<GetPublicKeyRequest, StreamObserver<PublicKey>> handler) {
      this.getPublicKeyHandler = handler;
    }

    @Override
    public void getPublicKey(
        GetPublicKeyRequest request, StreamObserver<PublicKey> responseObserver) {
      getPublicKeyHandler.accept(request, responseObserver);
    }
  }

  // A well-formed GetPublicKey response, echoing the requested name and format.
  private static PublicKey publicKeyResponse(GetPublicKeyRequest request) {
    return PublicKey.newBuilder()
        .setName(request.getName())
        .setPublicKeyFormat(request.getPublicKeyFormat())
        .setPublicKey(checksummedData(PUBLIC_KEY_DATA))
        .build();
  }

  @Before
  public void setUp() throws Exception {
    // Create a server, add service, start, and register for automatic graceful shutdown.
    String serverName = InProcessServerBuilder.generateName();
    grpcCleanup.register(
        InProcessServerBuilder.forName(serverName)
            .directExecutor()
            .addService(fakeKms)
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
    PublicKey publicKey =
        PublicKey.newBuilder().setPublicKey(checksummedData(PUBLIC_KEY_DATA)).build();
    GcpKmsUtil.verifyPublicKeyChecksum(publicKey);
  }

  @Test
  public void verifyPublicKeyChecksum_missingChecksum_throws() throws Exception {
    // ChecksummedData carries the data but no CRC32C checksum.
    PublicKey publicKey =
        PublicKey.newBuilder()
            .setPublicKey(ChecksummedData.newBuilder().setData(PUBLIC_KEY_DATA))
            .build();
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class, () -> GcpKmsUtil.verifyPublicKeyChecksum(publicKey));
    assertThat(e).hasMessageThat().contains("did not include a checksum");
  }

  @Test
  public void verifyPublicKeyChecksum_mismatchedChecksum_throws() throws Exception {
    long correctCrc32c =
        Hashing.crc32c().hashBytes(PUBLIC_KEY_DATA.asReadOnlyByteBuffer()).padToLong();
    PublicKey publicKey =
        PublicKey.newBuilder()
            .setPublicKey(
                ChecksummedData.newBuilder()
                    .setData(PUBLIC_KEY_DATA)
                    // Corrupt the checksum so it no longer matches the public key.
                    .setCrc32CChecksum(Int64Value.of(correctCrc32c + 1)))
            .build();
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class, () -> GcpKmsUtil.verifyPublicKeyChecksum(publicKey));
    assertThat(e).hasMessageThat().contains("does not match the public key");
  }

  // --- fetchPublicKey ---

  @Test
  public void fetchPublicKey_classicalKey_returnsPemKey() throws Exception {
    // A classical algorithm is served in PEM and returned as-is.
    fakeKms.setGetPublicKeyHandler(
        (request, responseObserver) -> {
          responseObserver.onNext(
              publicKeyResponse(request).toBuilder()
                  .setAlgorithm(CryptoKeyVersionAlgorithm.EC_SIGN_ED25519)
                  .build());
          responseObserver.onCompleted();
        });

    PublicKey publicKey = GcpKmsUtil.fetchPublicKey(kmsClient, VALID_KEY_NAME);

    assertThat(publicKey.getName()).isEqualTo(VALID_KEY_NAME);
    assertThat(publicKey.getPublicKeyFormat()).isEqualTo(PublicKey.PublicKeyFormat.PEM);
  }

  @Test
  public void fetchPublicKey_pemUnsupported_retriesInNistPqcFormat() throws Exception {
    // Keys that do not support PEM (e.g. SLH-DSA) report this; GcpKmsUtil retries in NIST_PQC.
    ByteString nistPqcData = ByteString.copyFromUtf8("raw slh dsa key bytes");
    fakeKms.setGetPublicKeyHandler(
        (request, responseObserver) -> {
          if (request.getPublicKeyFormat() != PublicKey.PublicKeyFormat.NIST_PQC) {
            responseObserver.onError(
                Status.INVALID_ARGUMENT
                    .withDescription("Only NIST_PQC format is supported for this algorithm.")
                    .asRuntimeException());
            return;
          }
          responseObserver.onNext(
              publicKeyResponse(request).toBuilder()
                  .setAlgorithm(CryptoKeyVersionAlgorithm.PQ_SIGN_SLH_DSA_SHA2_128S)
                  .setPublicKey(checksummedData(nistPqcData))
                  .build());
          responseObserver.onCompleted();
        });

    PublicKey publicKey = GcpKmsUtil.fetchPublicKey(kmsClient, VALID_KEY_NAME);

    assertThat(publicKey.getPublicKeyFormat()).isEqualTo(PublicKey.PublicKeyFormat.NIST_PQC);
    assertThat(publicKey.getPublicKey().getData()).isEqualTo(nistPqcData);
  }

  @Test
  public void fetchPublicKey_pemRequestFails_throws() throws Exception {
    // A failure that is not the "Only NIST_PQC format is supported" signal is not retried.
    fakeKms.setGetPublicKeyHandler(
        (request, responseObserver) ->
            responseObserver.onError(Status.INTERNAL.withDescription("boom").asRuntimeException()));

    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> GcpKmsUtil.fetchPublicKey(kmsClient, VALID_KEY_NAME));
    assertThat(e).hasMessageThat().contains("The KMS GetPublicKey failed");
  }

  @Test
  public void fetchPublicKey_nistPqcRetryFails_throws() throws Exception {
    // The PEM request signals NIST_PQC-only, but the NIST_PQC retry itself fails.
    fakeKms.setGetPublicKeyHandler(
        (request, responseObserver) -> {
          if (request.getPublicKeyFormat() != PublicKey.PublicKeyFormat.NIST_PQC) {
            responseObserver.onError(
                Status.INVALID_ARGUMENT
                    .withDescription("Only NIST_PQC format is supported for this algorithm.")
                    .asRuntimeException());
            return;
          }
          responseObserver.onError(Status.INTERNAL.withDescription("boom").asRuntimeException());
        });

    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> GcpKmsUtil.fetchPublicKey(kmsClient, VALID_KEY_NAME));
    assertThat(e).hasMessageThat().contains("The KMS GetPublicKey failed");
  }

  @Test
  public void fetchPublicKey_nameMismatch_throws() throws Exception {
    // The response carries a different key name than the one requested.
    fakeKms.setGetPublicKeyHandler(
        (request, responseObserver) -> {
          responseObserver.onNext(
              publicKeyResponse(request).toBuilder()
                  .setName(KEY_NAME_WITHOUT_VERSION)
                  .setAlgorithm(CryptoKeyVersionAlgorithm.EC_SIGN_ED25519)
                  .build());
          responseObserver.onCompleted();
        });

    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> GcpKmsUtil.fetchPublicKey(kmsClient, VALID_KEY_NAME));
    assertThat(e).hasMessageThat().contains("does not match the requested key name");
  }

  @Test
  public void fetchPublicKey_checksumMismatch_throws() throws Exception {
    long correctCrc32c =
        Hashing.crc32c().hashBytes(PUBLIC_KEY_DATA.asReadOnlyByteBuffer()).padToLong();
    fakeKms.setGetPublicKeyHandler(
        (request, responseObserver) -> {
          responseObserver.onNext(
              PublicKey.newBuilder()
                  .setName(request.getName())
                  .setPublicKeyFormat(request.getPublicKeyFormat())
                  .setAlgorithm(CryptoKeyVersionAlgorithm.EC_SIGN_ED25519)
                  // Corrupt the checksum so it no longer matches the public key.
                  .setPublicKey(
                      ChecksummedData.newBuilder()
                          .setData(PUBLIC_KEY_DATA)
                          .setCrc32CChecksum(Int64Value.of(correctCrc32c + 1)))
                  .build());
          responseObserver.onCompleted();
        });

    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> GcpKmsUtil.fetchPublicKey(kmsClient, VALID_KEY_NAME));
    assertThat(e).hasMessageThat().contains("The GetPublicKey checksum does not match");
  }
}
