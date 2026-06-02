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

import static org.junit.Assert.assertThrows;

import com.google.api.gax.core.NoCredentialsProvider;
import com.google.api.gax.grpc.GrpcTransportChannel;
import com.google.api.gax.rpc.FixedTransportChannelProvider;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.KeyManagementServiceGrpc.KeyManagementServiceImplBase;
import com.google.cloud.kms.v1.KeyManagementServiceSettings;
import com.google.crypto.tink.Mac;
import io.grpc.ManagedChannel;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
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
  private static final String KEY_NAME_WRONG_FORMAT =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions";

  @Rule public final GrpcCleanupRule grpcCleanup = new GrpcCleanupRule();

  private KeyManagementServiceClient kmsClient;

  @Before
  public void setUp() throws Exception {
    String serverName = InProcessServerBuilder.generateName();
    grpcCleanup.register(
        InProcessServerBuilder.forName(serverName)
            .directExecutor()
            .addService(new KeyManagementServiceImplBase() {})
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

  // Placeholder — will be replaced by real tests in the next commit.
  @Test
  public void computeMac_notYetImplemented() throws Exception {
    Mac gcpKmsMac =
        GcpKmsMac.builder().setKeyName(KEY_NAME).setKeyManagementServiceClient(kmsClient).build();
    assertThrows(UnsupportedOperationException.class, () -> gcpKmsMac.computeMac(new byte[0]));
  }

  // Placeholder — will be replaced by real tests in the next commit.
  @Test
  public void verifyMac_notYetImplemented() throws Exception {
    Mac gcpKmsMac =
        GcpKmsMac.builder().setKeyName(KEY_NAME).setKeyManagementServiceClient(kmsClient).build();
    assertThrows(
        UnsupportedOperationException.class, () -> gcpKmsMac.verifyMac(new byte[0], new byte[0]));
  }
}
