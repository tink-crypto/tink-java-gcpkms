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

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.api.gax.core.NoCredentialsProvider;
import com.google.api.gax.grpc.GrpcTransportChannel;
import com.google.api.gax.rpc.FixedTransportChannelProvider;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.KeyManagementServiceGrpc.KeyManagementServiceImplBase;
import com.google.cloud.kms.v1.KeyManagementServiceSettings;
import com.google.cloud.kms.v1.MacSignRequest;
import com.google.cloud.kms.v1.MacSignResponse;
import com.google.cloud.kms.v1.MacVerifyRequest;
import com.google.cloud.kms.v1.MacVerifyResponse;
import com.google.common.hash.Hashing;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.mac.PredefinedMacParameters;
import com.google.protobuf.ByteString;
import com.google.protobuf.Int64Value;
import io.grpc.ManagedChannel;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import io.grpc.stub.StreamObserver;
import io.grpc.testing.GrpcCleanupRule;
import java.security.GeneralSecurityException;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class GcpKmsMacTest {

  private static final String KEY_NAME =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions/1";
  private static final String KEY_NAME_WITHOUT_VERSION =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1";
  private static final String KEY_NAME_FOR_RPC_ERROR_SIGN =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions/2";
  private static final String KEY_NAME_FOR_DATA_CRC32C_NOT_VERIFIED =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions/3";
  private static final String KEY_NAME_FOR_MAC_CRC32C_MISMATCH =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions/4";
  private static final String KEY_NAME_FOR_KEY_NAME_MISMATCH_SIGN =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions/5";
  private static final String KEY_NAME_FOR_RPC_ERROR_VERIFY =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions/6";
  private static final String KEY_NAME_FOR_VERIFY_DATA_CRC32C_NOT_VERIFIED =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions/7";
  private static final String KEY_NAME_FOR_VERIFY_MAC_CRC32C_NOT_VERIFIED =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions/8";
  private static final String KEY_NAME_FOR_VERIFY_SUCCESS_INTEGRITY_NOT_VERIFIED =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions/9";
  private static final String KEY_NAME_FOR_KEY_NAME_MISMATCH_VERIFY =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions/10";
  private static final String KEY_NAME_WRONG_FORMAT =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions";

  /** This rule manages automatic graceful shutdown for the registered servers and channels. */
  @Rule public final GrpcCleanupRule grpcCleanup = new GrpcCleanupRule();

  private final byte[] macData = "data".getBytes(UTF_8);
  private Mac backingMac;
  private KeyManagementServiceClient kmsClient;

  /** Fake KMS server that simulates macSign and macVerify RPCs. */
  public class FakeKmsImpl extends KeyManagementServiceImplBase {

    @Override
    public void macSign(MacSignRequest request, StreamObserver<MacSignResponse> responseObserver) {
      try {
        if (request.getName().equals(KEY_NAME_FOR_RPC_ERROR_SIGN)) {
          throw new GeneralSecurityException("testing RPC error for macSign.");
        }

        byte[] macBytes = backingMac.computeMac(request.getData().toByteArray());
        long macCrc32c = Hashing.crc32c().hashBytes(macBytes).padToLong();

        MacSignResponse.Builder builder =
            MacSignResponse.newBuilder()
                .setName(request.getName())
                .setMac(ByteString.copyFrom(macBytes))
                .setMacCrc32C(Int64Value.of(macCrc32c))
                .setVerifiedDataCrc32C(true);

        if (request.getName().equals(KEY_NAME_FOR_DATA_CRC32C_NOT_VERIFIED)) {
          builder.setVerifiedDataCrc32C(false);
        }
        if (request.getName().equals(KEY_NAME_FOR_MAC_CRC32C_MISMATCH)) {
          builder.setMacCrc32C(Int64Value.of(macCrc32c + 1));
        }
        if (request.getName().equals(KEY_NAME_FOR_KEY_NAME_MISMATCH_SIGN)) {
          builder.setName(KEY_NAME);
        }

        responseObserver.onNext(builder.build());
        responseObserver.onCompleted();
      } catch (GeneralSecurityException e) {
        responseObserver.onError(e);
      }
    }

    @Override
    public void macVerify(
        MacVerifyRequest request, StreamObserver<MacVerifyResponse> responseObserver) {
      try {
        if (request.getName().equals(KEY_NAME_FOR_RPC_ERROR_VERIFY)) {
          throw new GeneralSecurityException("testing RPC error for macVerify.");
        }

        boolean success;
        try {
          backingMac.verifyMac(request.getMac().toByteArray(), request.getData().toByteArray());
          success = true;
        } catch (GeneralSecurityException e) {
          success = false;
        }

        MacVerifyResponse.Builder builder =
            MacVerifyResponse.newBuilder()
                .setName(request.getName())
                .setSuccess(success)
                .setVerifiedDataCrc32C(true)
                .setVerifiedMacCrc32C(true)
                .setVerifiedSuccessIntegrity(success);

        if (request.getName().equals(KEY_NAME_FOR_VERIFY_DATA_CRC32C_NOT_VERIFIED)) {
          builder.setVerifiedDataCrc32C(false);
        }
        if (request.getName().equals(KEY_NAME_FOR_VERIFY_MAC_CRC32C_NOT_VERIFIED)) {
          builder.setVerifiedMacCrc32C(false);
        }
        if (request.getName().equals(KEY_NAME_FOR_VERIFY_SUCCESS_INTEGRITY_NOT_VERIFIED)) {
          builder.setVerifiedSuccessIntegrity(!success);
        }
        if (request.getName().equals(KEY_NAME_FOR_KEY_NAME_MISMATCH_VERIFY)) {
          builder.setName(KEY_NAME);
        }

        responseObserver.onNext(builder.build());
        responseObserver.onCompleted();
      } catch (GeneralSecurityException e) {
        responseObserver.onError(e);
      }
    }
  }

  @Before
  public void setUp() throws Exception {
    MacConfig.register();
    KeysetHandle keysetHandle =
        KeysetHandle.generateNew(PredefinedMacParameters.HMAC_SHA256_128BITTAG);
    backingMac = keysetHandle.getPrimitive(RegistryConfiguration.get(), Mac.class);

    String serverName = InProcessServerBuilder.generateName();
    grpcCleanup.register(
        InProcessServerBuilder.forName(serverName)
            .directExecutor()
            .addService(new FakeKmsImpl())
            .build()
            .start());

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

  // --- Builder validation tests ---

  @Test
  public void keyNameNotSet_throws() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> GcpKmsMac.builder().setKeyManagementServiceClient(kmsClient).build());
  }

  @Test
  public void keyNameInWrongFormat_throws() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            GcpKmsMac.builder()
                .setKeyName(KEY_NAME_WRONG_FORMAT)
                .setKeyManagementServiceClient(kmsClient)
                .build());
  }

  @Test
  public void keyNameWithoutCryptoKeyVersion_throws() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            GcpKmsMac.builder()
                .setKeyName(KEY_NAME_WITHOUT_VERSION)
                .setKeyManagementServiceClient(kmsClient)
                .build());
  }

  @Test
  public void keyNameIsEmpty_throws() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> GcpKmsMac.builder().setKeyName("").setKeyManagementServiceClient(kmsClient).build());
  }

  @Test
  public void kmsClientNotGiven_throws() throws Exception {
    assertThrows(
        GeneralSecurityException.class, () -> GcpKmsMac.builder().setKeyName(KEY_NAME).build());
  }

  // --- computeMac error tests ---

  @Test
  public void computeMac_macSignRpcFails_throws() throws GeneralSecurityException {
    Mac gcpKmsMac =
        GcpKmsMac.builder()
            .setKeyName(KEY_NAME_FOR_RPC_ERROR_SIGN)
            .setKeyManagementServiceClient(kmsClient)
            .build();

    assertThrows(GeneralSecurityException.class, () -> gcpKmsMac.computeMac(macData));
  }

  @Test
  public void computeMac_inputCrc32cNotVerified_throws() throws GeneralSecurityException {
    Mac gcpKmsMac =
        GcpKmsMac.builder()
            .setKeyName(KEY_NAME_FOR_DATA_CRC32C_NOT_VERIFIED)
            .setKeyManagementServiceClient(kmsClient)
            .build();

    assertThrows(GeneralSecurityException.class, () -> gcpKmsMac.computeMac(macData));
  }

  @Test
  public void computeMac_macCrc32cMismatch_throws() throws GeneralSecurityException {
    Mac gcpKmsMac =
        GcpKmsMac.builder()
            .setKeyName(KEY_NAME_FOR_MAC_CRC32C_MISMATCH)
            .setKeyManagementServiceClient(kmsClient)
            .build();

    assertThrows(GeneralSecurityException.class, () -> gcpKmsMac.computeMac(macData));
  }

  @Test
  public void computeMac_keyNameMismatch_throws() throws GeneralSecurityException {
    Mac gcpKmsMac =
        GcpKmsMac.builder()
            .setKeyName(KEY_NAME_FOR_KEY_NAME_MISMATCH_SIGN)
            .setKeyManagementServiceClient(kmsClient)
            .build();

    assertThrows(GeneralSecurityException.class, () -> gcpKmsMac.computeMac(macData));
  }

  @Test
  public void computeMac_dataTooLarge_fails() throws GeneralSecurityException {
    Mac gcpKmsMac =
        GcpKmsMac.builder().setKeyName(KEY_NAME).setKeyManagementServiceClient(kmsClient).build();

    byte[] largeData = new byte[GcpKmsMac.MAX_MAC_DATA_SIZE + 1];

    GeneralSecurityException e =
        assertThrows(GeneralSecurityException.class, () -> gcpKmsMac.computeMac(largeData));
    assertThat(e).hasMessageThat().contains("larger than the allowed size");
  }

  // --- verifyMac error tests ---

  @Test
  public void verifyMac_macVerifyRpcFails_throws() throws GeneralSecurityException {
    Mac gcpKmsMac =
        GcpKmsMac.builder()
            .setKeyName(KEY_NAME_FOR_RPC_ERROR_VERIFY)
            .setKeyManagementServiceClient(kmsClient)
            .build();

    byte[] mac = gcpKmsMac.computeMac(macData);

    assertThrows(GeneralSecurityException.class, () -> gcpKmsMac.verifyMac(mac, macData));
  }

  @Test
  public void verifyMac_dataCrc32cNotVerified_throws() throws GeneralSecurityException {
    Mac gcpKmsMac =
        GcpKmsMac.builder()
            .setKeyName(KEY_NAME_FOR_VERIFY_DATA_CRC32C_NOT_VERIFIED)
            .setKeyManagementServiceClient(kmsClient)
            .build();

    byte[] mac = gcpKmsMac.computeMac(macData);

    assertThrows(GeneralSecurityException.class, () -> gcpKmsMac.verifyMac(mac, macData));
  }

  @Test
  public void verifyMac_macCrc32cNotVerified_throws() throws GeneralSecurityException {
    Mac gcpKmsMac =
        GcpKmsMac.builder()
            .setKeyName(KEY_NAME_FOR_VERIFY_MAC_CRC32C_NOT_VERIFIED)
            .setKeyManagementServiceClient(kmsClient)
            .build();

    byte[] mac = gcpKmsMac.computeMac(macData);

    assertThrows(GeneralSecurityException.class, () -> gcpKmsMac.verifyMac(mac, macData));
  }

  @Test
  public void verifyMac_successIntegrityNotVerified_throws() throws GeneralSecurityException {
    Mac gcpKmsMac =
        GcpKmsMac.builder()
            .setKeyName(KEY_NAME_FOR_VERIFY_SUCCESS_INTEGRITY_NOT_VERIFIED)
            .setKeyManagementServiceClient(kmsClient)
            .build();

    byte[] mac = gcpKmsMac.computeMac(macData);

    assertThrows(GeneralSecurityException.class, () -> gcpKmsMac.verifyMac(mac, macData));
  }

  @Test
  public void verifyMac_keyNameMismatch_throws() throws GeneralSecurityException {
    Mac gcpKmsMac =
        GcpKmsMac.builder()
            .setKeyName(KEY_NAME_FOR_KEY_NAME_MISMATCH_VERIFY)
            .setKeyManagementServiceClient(kmsClient)
            .build();

    byte[] mac = gcpKmsMac.computeMac(macData);

    assertThrows(GeneralSecurityException.class, () -> gcpKmsMac.verifyMac(mac, macData));
  }

  @Test
  public void verifyMac_dataTooLarge_fails() throws GeneralSecurityException {
    Mac gcpKmsMac =
        GcpKmsMac.builder().setKeyName(KEY_NAME).setKeyManagementServiceClient(kmsClient).build();

    byte[] largeData = new byte[GcpKmsMac.MAX_MAC_DATA_SIZE + 1];

    GeneralSecurityException e =
        assertThrows(GeneralSecurityException.class, () -> gcpKmsMac.verifyMac(macData, largeData));
    assertThat(e).hasMessageThat().contains("larger than the allowed size");
  }

  @Test
  public void verifyMac_macTooLarge_fails() throws GeneralSecurityException {
    Mac gcpKmsMac =
        GcpKmsMac.builder().setKeyName(KEY_NAME).setKeyManagementServiceClient(kmsClient).build();

    byte[] largeMac = new byte[GcpKmsMac.MAX_MAC_VALUE_SIZE + 1];

    GeneralSecurityException e =
        assertThrows(GeneralSecurityException.class, () -> gcpKmsMac.verifyMac(largeMac, macData));
    assertThat(e).hasMessageThat().contains("larger than the allowed size");
  }

  // --- computeMac and verifyMac success and failure tests ---

  @Test
  public void computeAndVerifyMac_success() throws GeneralSecurityException {
    Mac gcpKmsMac =
        GcpKmsMac.builder().setKeyName(KEY_NAME).setKeyManagementServiceClient(kmsClient).build();

    byte[] mac = gcpKmsMac.computeMac(macData);
    gcpKmsMac.verifyMac(mac, macData); // Must not throw.

    // HMAC is deterministic: the result must match the backing MAC directly.
    assertThat(mac).isEqualTo(backingMac.computeMac(macData));
  }

  @Test
  public void verifyMac_wrongData_fails() throws GeneralSecurityException {
    Mac gcpKmsMac =
        GcpKmsMac.builder().setKeyName(KEY_NAME).setKeyManagementServiceClient(kmsClient).build();

    byte[] wrongData = "wrong data for mac".getBytes(UTF_8);
    byte[] mac = gcpKmsMac.computeMac(macData);

    assertThrows(GeneralSecurityException.class, () -> gcpKmsMac.verifyMac(mac, wrongData));
  }

  @Test
  public void verifyMac_wrongMac_fails() throws GeneralSecurityException {
    Mac gcpKmsMac =
        GcpKmsMac.builder().setKeyName(KEY_NAME).setKeyManagementServiceClient(kmsClient).build();

    byte[] wrongMac = "this is not a valid mac".getBytes(UTF_8);

    assertThrows(GeneralSecurityException.class, () -> gcpKmsMac.verifyMac(wrongMac, macData));
  }
}
