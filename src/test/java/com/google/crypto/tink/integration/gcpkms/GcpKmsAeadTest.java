// Copyright 2023 Google LLC
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
import static java.util.Arrays.asList;
import static org.junit.Assert.assertThrows;

import com.google.api.gax.core.NoCredentialsProvider;
import com.google.api.gax.grpc.GrpcTransportChannel;
import com.google.api.gax.rpc.FixedTransportChannelProvider;
import com.google.cloud.kms.v1.DecryptRequest;
import com.google.cloud.kms.v1.DecryptResponse;
import com.google.cloud.kms.v1.EncryptRequest;
import com.google.cloud.kms.v1.EncryptResponse;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.KeyManagementServiceGrpc.KeyManagementServiceImplBase;
import com.google.cloud.kms.v1.KeyManagementServiceSettings;
import com.google.common.hash.Hashing;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.PredefinedAeadParameters;
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
public final class GcpKmsAeadTest {

  private static final String KEY_NAME_WRONG_FORMAT =
      "projects/cloudkms-test/locations/global/keyRings/TinkKmsLib/cryptoKeys";

  private static final String KEY_NAME_VALID =
      "projects/cloudkms-test/locations/global/keyRings/TinkKmsLib/cryptoKeys/key1";

  private static final String KEY_NAME_VALID_2 =
      "projects/cloudkms-test/locations/global/keyRings/TinkKmsLib/cryptoKeys/key2";

  private static final String KEY_NAME_KEY_NAME_NOT_SET =
      "projects/cloudkms-test/locations/global/keyRings/TinkKmsLib/cryptoKeys/key3";

  private static final String KEY_NAME_PLAINTEXT_NOT_VERIFIED =
      "projects/cloudkms-test/locations/global/keyRings/TinkKmsLib/cryptoKeys/key4";

  private static final String KEY_NAME_ADDITIONAL_AUTHENTICATED_DATA_NOT_VERIFIED =
      "projects/cloudkms-test/locations/global/keyRings/TinkKmsLib/cryptoKeys/key5";

  private static final String KEY_NAME_INVALID_CIPHERTEXT_CRC =
      "projects/cloudkms-test/locations/global/keyRings/TinkKmsLib/cryptoKeys/key6";

  private static final String KEY_NAME_INVALID_PLAINTEXT_CRC =
      "projects/cloudkms-test/locations/global/keyRings/TinkKmsLib/cryptoKeys/key9";

  // Implement a fake KeyManagementService.
  public static class FakeKmsImpl extends KeyManagementServiceImplBase {
    private static final Aead aead = createAead();

    private static final Aead createAead() {
      try {
        return KeysetHandle.generateNew(PredefinedAeadParameters.AES256_GCM)
            .getPrimitive(Aead.class);
      } catch (GeneralSecurityException e) {
        throw new RuntimeException(e);
      }
    }

    @Override
    public void encrypt(EncryptRequest request, StreamObserver<EncryptResponse> responseObserver) {
      EncryptResponse.Builder builder = EncryptResponse.newBuilder();

      if (!request.getName().equals(KEY_NAME_KEY_NAME_NOT_SET)) {
        builder.setName(request.getName());
      }

      try {
        byte[] plaintext = request.getPlaintext().toByteArray();
        if (request.hasPlaintextCrc32C()
            && !request.getName().equals(KEY_NAME_PLAINTEXT_NOT_VERIFIED)) {
          long plaintextCrc32c = Hashing.crc32c().hashBytes(plaintext).padToLong();
          if (request.getPlaintextCrc32C().getValue() != plaintextCrc32c) {
            throw new GeneralSecurityException("Invalid argument, plaintext CRC mismatch.");
          }
          builder.setVerifiedPlaintextCrc32C(true);
        }
        byte[] associatedData = request.getAdditionalAuthenticatedData().toByteArray();
        if (request.hasAdditionalAuthenticatedDataCrc32C()
            && !request.getName().equals(KEY_NAME_ADDITIONAL_AUTHENTICATED_DATA_NOT_VERIFIED)) {
          long associatedDataCrc32c = Hashing.crc32c().hashBytes(associatedData).padToLong();
          if (request.getAdditionalAuthenticatedDataCrc32C().getValue() != associatedDataCrc32c) {
            throw new GeneralSecurityException(
                "Invalid argument, additional authenticated data CRC mismatch.");
          }
          builder.setVerifiedAdditionalAuthenticatedDataCrc32C(true);
        }

        byte[] ciphertext = aead.encrypt(plaintext, associatedData);
        builder.setCiphertext(ByteString.copyFrom(ciphertext));

        long ciphertextCrc32c = Hashing.crc32c().hashBytes(ciphertext).padToLong();
        if (request.getName().equals(KEY_NAME_INVALID_CIPHERTEXT_CRC)) {
          ciphertextCrc32c++;
        }
        builder.setCiphertextCrc32C(Int64Value.of(ciphertextCrc32c));

        responseObserver.onNext(builder.build());
        responseObserver.onCompleted();
      } catch (GeneralSecurityException e) {
        responseObserver.onError(e);
      }
    }

    @Override
    public void decrypt(DecryptRequest request, StreamObserver<DecryptResponse> responseObserver) {
      DecryptResponse.Builder builder = DecryptResponse.newBuilder();
      try {
        byte[] ciphertext = request.getCiphertext().toByteArray();
        if (request.hasCiphertextCrc32C()) {
          long ciphertextCrc32c = Hashing.crc32c().hashBytes(ciphertext).padToLong();
          if (request.getCiphertextCrc32C().getValue() != ciphertextCrc32c) {
            throw new GeneralSecurityException("invalid argument, ciphertext CRC mismatch.");
          }
        }

        byte[] associatedData = request.getAdditionalAuthenticatedData().toByteArray();
        if (request.hasAdditionalAuthenticatedDataCrc32C()) {
          long associatedDataCrc32c = Hashing.crc32c().hashBytes(associatedData).padToLong();
          if (request.getAdditionalAuthenticatedDataCrc32C().getValue() != associatedDataCrc32c) {
            throw new GeneralSecurityException(
                "Invalid argument, additional authenticated data CRC mismatch.");
          }
        }

        byte[] plaintext = aead.decrypt(ciphertext, associatedData);
        builder.setPlaintext(ByteString.copyFrom(plaintext));

        long plaintextCrc32c = Hashing.crc32c().hashBytes(plaintext).padToLong();
        if (request.getName().equals(KEY_NAME_INVALID_PLAINTEXT_CRC)) {
          plaintextCrc32c++;
        }
        builder.setPlaintextCrc32C(Int64Value.of(plaintextCrc32c));

        responseObserver.onNext(builder.build());
        responseObserver.onCompleted();
      } catch (GeneralSecurityException e) {
        responseObserver.onError(e);
      }
    }
  }

  private KeyManagementServiceClient kmsClient;

  /** This rule manages automatic graceful shutdown for the registered servers and channels. */
  @Rule public final GrpcCleanupRule grpcCleanup = new GrpcCleanupRule();

  @Before
  public void setUpClass() throws Exception {
    AeadConfig.register();

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
  public void kmsAead_works() throws Exception {
    FakeCloudKms fakeKms = new FakeCloudKms(asList(KEY_NAME_VALID));

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    Aead kmsAead = new GcpKmsAead(fakeKms, KEY_NAME_VALID);

    byte[] ciphertext = kmsAead.encrypt(plaintext, associatedData);
    byte[] decrypted = kmsAead.decrypt(ciphertext, associatedData);
    assertThat(decrypted).isEqualTo(plaintext);

    byte[] associatedData2 = "associatedData2".getBytes(UTF_8);
    assertThrows(
        GeneralSecurityException.class, () -> kmsAead.decrypt(ciphertext, associatedData2));

    ciphertext[7] = (byte) (ciphertext[7] ^ 42);
    assertThrows(GeneralSecurityException.class, () -> kmsAead.decrypt(ciphertext, associatedData));
  }

  @Test
  public void builderWithSetCloudKms_sameAsPublicConstructor() throws Exception {
    FakeCloudKms fakeKms = new FakeCloudKms(asList(KEY_NAME_VALID));

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    Aead kmsAead1 = new GcpKmsAead(fakeKms, KEY_NAME_VALID);
    Aead kmsAead2 = GcpKmsAead.builder().setCloudKms(fakeKms).setKeyName(KEY_NAME_VALID).build();

    byte[] ciphertext = kmsAead1.encrypt(plaintext, associatedData);
    byte[] decrypted = kmsAead2.decrypt(ciphertext, associatedData);
    assertThat(decrypted).isEqualTo(plaintext);
  }

  @Test
  public void kmsAeadGrpc_keyNameNotSet() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> GcpKmsAead.builder().setKeyManagementServiceClient(kmsClient).build());
  }

  @Test
  public void kmsAeadGrpc_keyNameIsEmpty() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> GcpKmsAead.builder().setKeyName("").setKeyManagementServiceClient(kmsClient).build());
  }

  @Test
  public void kmsAeadGrpc_keyNameInWrongFormat() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            GcpKmsAead.builder()
                .setKeyName(KEY_NAME_WRONG_FORMAT)
                .setKeyManagementServiceClient(kmsClient)
                .build());
  }

  @Test
  public void kmsAeadGrpc_noKmsClientIsGiven() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> GcpKmsAead.builder().setKeyName(KEY_NAME_VALID).build());
  }

  @Test
  public void kmsAeadGrpc_bothKmsCliensAreGiven() throws Exception {
    FakeCloudKms fakeKms = new FakeCloudKms(asList(KEY_NAME_VALID));
    assertThrows(
        GeneralSecurityException.class,
        () ->
            GcpKmsAead.builder()
                .setKeyName(KEY_NAME_VALID)
                .setCloudKms(fakeKms)
                .setKeyManagementServiceClient(kmsClient)
                .build());
  }

  @Test
  public void kmsAeadGrpc_works() throws Exception {
    Aead kmsAead =
        GcpKmsAead.builder()
            .setKeyName(KEY_NAME_VALID)
            .setKeyManagementServiceClient(kmsClient)
            .build();

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] associatedData2 = "associatedData2".getBytes(UTF_8);
    byte[] ciphertext = kmsAead.encrypt(plaintext, associatedData);
    byte[] decrypted = kmsAead.decrypt(ciphertext, associatedData);

    assertThat(decrypted).isEqualTo(plaintext);
    assertThrows(
        GeneralSecurityException.class, () -> kmsAead.decrypt(ciphertext, associatedData2));
    ciphertext[7] = (byte) (ciphertext[7] ^ 42);
    assertThrows(GeneralSecurityException.class, () -> kmsAead.decrypt(ciphertext, associatedData));
  }

  @Test
  public void kmsAeadGrpc_worksWithBytes() throws Exception {
    Aead kmsAead =
        GcpKmsAead.builder()
            .setKeyName(KEY_NAME_VALID)
            .setKeyManagementServiceClient(kmsClient)
            .build();

    byte[] plaintext = {(byte) 1, (byte) 2, (byte) 3, (byte) 4, (byte) 5, (byte) 6};
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] associatedData2 = "associatedData2".getBytes(UTF_8);
    byte[] ciphertext = kmsAead.encrypt(plaintext, associatedData);
    byte[] decrypted = kmsAead.decrypt(ciphertext, associatedData);

    assertThat(decrypted).isEqualTo(plaintext);
    assertThrows(
        GeneralSecurityException.class, () -> kmsAead.decrypt(ciphertext, associatedData2));
    ciphertext[2] = (byte) (ciphertext[2] ^ 42);
    assertThrows(GeneralSecurityException.class, () -> kmsAead.decrypt(ciphertext, associatedData));
  }

  @Test
  public void kmsAeadGrpc_encryptDecryptEmptyString_success() throws Exception {
    Aead kmsAead =
        GcpKmsAead.builder()
            .setKeyName(KEY_NAME_VALID)
            .setKeyManagementServiceClient(kmsClient)
            .build();

    byte[] plaintext = "".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = kmsAead.encrypt(plaintext, associatedData);
    byte[] decrypted = kmsAead.decrypt(ciphertext, associatedData);
    assertThat(decrypted).isEqualTo(plaintext);
  }

  @Test
  public void kmsAead_encryptDecryptEmptyString_success() throws Exception {
    FakeCloudKms fakeKms = new FakeCloudKms(asList(KEY_NAME_VALID));

    byte[] plaintext = "".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    Aead kmsAead = new GcpKmsAead(fakeKms, KEY_NAME_VALID);

    byte[] ciphertext = kmsAead.encrypt(plaintext, associatedData);
    byte[] decrypted = kmsAead.decrypt(ciphertext, associatedData);
    assertThat(decrypted).isEqualTo(plaintext);
  }

  @Test
  public void twoKmsAeads_canOnlyDecryptTheirOwnCiphertext() throws Exception {
    FakeCloudKms fakeKms = new FakeCloudKms(asList(KEY_NAME_VALID, KEY_NAME_VALID_2));

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    Aead kmsAead = new GcpKmsAead(fakeKms, KEY_NAME_VALID);
    byte[] ciphertext = kmsAead.encrypt(plaintext, associatedData);

    Aead kmsAead2 = new GcpKmsAead(fakeKms, KEY_NAME_VALID_2);
    byte[] ciphertext2 = kmsAead2.encrypt(plaintext, associatedData);

    assertThat(kmsAead.decrypt(ciphertext, associatedData)).isEqualTo(plaintext);
    assertThat(kmsAead2.decrypt(ciphertext2, associatedData)).isEqualTo(plaintext);

    assertThrows(
        GeneralSecurityException.class, () -> kmsAead2.decrypt(ciphertext, associatedData));
    assertThrows(
        GeneralSecurityException.class, () -> kmsAead.decrypt(ciphertext2, associatedData));
  }

  @Test
  public void kmsAeadGrpc_wrongKeyNameInReponse() throws Exception {
    Aead kmsAead =
        GcpKmsAead.builder()
            .setKeyName(KEY_NAME_KEY_NAME_NOT_SET)
            .setKeyManagementServiceClient(kmsClient)
            .build();

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    assertThrows(GeneralSecurityException.class, () -> kmsAead.encrypt(plaintext, associatedData));
  }

  @Test
  public void kmsAeadGrpc_plaintextNotVerified() throws Exception {
    Aead kmsAead =
        GcpKmsAead.builder()
            .setKeyName(KEY_NAME_PLAINTEXT_NOT_VERIFIED)
            .setKeyManagementServiceClient(kmsClient)
            .build();

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    assertThrows(GeneralSecurityException.class, () -> kmsAead.encrypt(plaintext, associatedData));
  }

  @Test
  public void kmsAeadGrpc_additionalAuthenticatedDataNotVerified() throws Exception {
    Aead kmsAead =
        GcpKmsAead.builder()
            .setKeyName(KEY_NAME_ADDITIONAL_AUTHENTICATED_DATA_NOT_VERIFIED)
            .setKeyManagementServiceClient(kmsClient)
            .build();

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    assertThrows(GeneralSecurityException.class, () -> kmsAead.encrypt(plaintext, associatedData));
  }

  @Test
  public void kmsAeadGrpc_invalidCiphertextCrc() throws Exception {
    Aead kmsAead =
        GcpKmsAead.builder()
            .setKeyName(KEY_NAME_INVALID_CIPHERTEXT_CRC)
            .setKeyManagementServiceClient(kmsClient)
            .build();

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    assertThrows(GeneralSecurityException.class, () -> kmsAead.encrypt(plaintext, associatedData));
  }

  @Test
  public void kmsAeadGrpc_invalidPlaintextCrc() throws Exception {
    Aead kmsAead =
        GcpKmsAead.builder()
            .setKeyName(KEY_NAME_INVALID_PLAINTEXT_CRC)
            .setKeyManagementServiceClient(kmsClient)
            .build();

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = kmsAead.encrypt(plaintext, associatedData);
    assertThrows(GeneralSecurityException.class, () -> kmsAead.decrypt(ciphertext, associatedData));
  }
}
