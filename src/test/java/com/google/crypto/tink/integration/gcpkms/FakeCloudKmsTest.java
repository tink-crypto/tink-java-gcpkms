// Copyright 2022 Google LLC
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

import com.google.api.services.cloudkms.v1.CloudKMS;
import com.google.api.services.cloudkms.v1.model.DecryptRequest;
import com.google.api.services.cloudkms.v1.model.DecryptResponse;
import com.google.api.services.cloudkms.v1.model.EncryptRequest;
import com.google.api.services.cloudkms.v1.model.EncryptResponse;
import com.google.common.hash.Hashing;
import com.google.crypto.tink.aead.AeadConfig;
import java.io.IOException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class FakeCloudKmsTest {

  private static final String KEY_ID =
      "projects/tink-test/locations/global/keyRings/unit-test/cryptoKeys/aead-key";
  private static final String KEY_ID_2 =
      "projects/tink-test/locations/global/keyRings/unit-test/cryptoKeys/aead-key-2";

  @BeforeClass
  public static void setUpClass() throws Exception {
    AeadConfig.register();
  }

  @Test
  public void testEncryptDecryptWithValidKeyId_success() throws Exception {
    CloudKMS kms = new FakeCloudKms(asList(KEY_ID));

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    EncryptRequest encRequest =
        new EncryptRequest()
            .encodePlaintext(plaintext)
            .encodeAdditionalAuthenticatedData(associatedData);

    EncryptResponse encResponse =
        kms.projects().locations().keyRings().cryptoKeys().encrypt(KEY_ID, encRequest).execute();

    DecryptRequest decRequest =
        new DecryptRequest()
            .encodeCiphertext(encResponse.decodeCiphertext())
            .encodeAdditionalAuthenticatedData(associatedData);

    DecryptResponse decResponse =
        kms.projects().locations().keyRings().cryptoKeys().decrypt(KEY_ID, decRequest).execute();

    assertThat(decResponse.decodePlaintext()).isEqualTo(plaintext);
  }

  @Test
  public void testEncryptDecryptWithInvalidAssociatedData_fails() throws Exception {
    CloudKMS kms = new FakeCloudKms(asList(KEY_ID));

    EncryptRequest encRequest =
        new EncryptRequest()
            .encodePlaintext("plaintext".getBytes(UTF_8))
            .encodeAdditionalAuthenticatedData("associatedData".getBytes(UTF_8));

    EncryptResponse encResponse =
        kms.projects().locations().keyRings().cryptoKeys().encrypt(KEY_ID, encRequest).execute();

    DecryptRequest decRequestWithInvalidAssociatedData =
        new DecryptRequest()
            .encodeCiphertext(encResponse.decodeCiphertext())
            .encodeAdditionalAuthenticatedData("invalidAssociatedData".getBytes(UTF_8));

    CloudKMS.Projects.Locations.KeyRings.CryptoKeys.Decrypt dec =
        kms.projects()
            .locations()
            .keyRings()
            .cryptoKeys()
            .decrypt(KEY_ID, decRequestWithInvalidAssociatedData);
    assertThrows(IOException.class, dec::execute);
  }

  long getCrc32c(byte[] data) {
    return Hashing.crc32c().hashBytes(data).padToLong();
  }

  @Test
  public void testEncryptDecrytWithValidCrc_isNotVerified() throws Exception {
    CloudKMS kms = new FakeCloudKms(asList(KEY_ID));

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    EncryptRequest encRequest =
        new EncryptRequest()
            .encodePlaintext(plaintext)
            .setPlaintextCrc32c(getCrc32c(plaintext))
            .encodeAdditionalAuthenticatedData(associatedData)
            .setAdditionalAuthenticatedDataCrc32c(getCrc32c(associatedData));

    EncryptResponse encResponse =
        kms.projects().locations().keyRings().cryptoKeys().encrypt(KEY_ID, encRequest).execute();

    byte[] ciphertext = encResponse.decodeCiphertext();

    DecryptRequest decRequest =
        new DecryptRequest()
            .encodeCiphertext(ciphertext)
            .setCiphertextCrc32c(getCrc32c(ciphertext))
            .encodeAdditionalAuthenticatedData(associatedData)
            .setAdditionalAuthenticatedDataCrc32c(getCrc32c(associatedData));

    DecryptResponse decResponse =
        kms.projects().locations().keyRings().cryptoKeys().decrypt(KEY_ID, decRequest).execute();

    assertThat(decResponse.decodePlaintext()).isEqualTo(plaintext);

    // TODO(ckl): Add CRC validation to FakeCloudKms.
    assertThat(encResponse.getVerifiedPlaintextCrc32c()).isNull();
    assertThat(encResponse.getVerifiedAdditionalAuthenticatedDataCrc32c()).isNull();

    // TODO(ckl): Set CRC in response from FakeCloudKms.
    assertThat(encResponse.getCiphertextCrc32c()).isNull();
    assertThat(decResponse.getPlaintextCrc32c()).isNull();
  }

  @Test
  public void testEncryptWithInvalidCrc_successBecauseCrcIsNotVerified() throws Exception {
    CloudKMS kms = new FakeCloudKms(asList(KEY_ID));

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    Long invalidCrc = Long.valueOf(123);

    EncryptRequest encRequestWithInvalidPlaintextCrc =
        new EncryptRequest()
            .encodePlaintext(plaintext)
            .setPlaintextCrc32c(invalidCrc)
            .encodeAdditionalAuthenticatedData(associatedData);

    // TODO(ckl): Add CRC validation to FakeCloudKms. This should throw.
    EncryptResponse encResponse =
        kms.projects()
            .locations()
            .keyRings()
            .cryptoKeys()
            .encrypt(KEY_ID, encRequestWithInvalidPlaintextCrc)
            .execute();
    assertThat(encResponse).isNotNull();

    EncryptRequest encRequestWithInvalidAssociatedDataCrc =
        new EncryptRequest()
            .encodePlaintext(plaintext)
            .encodeAdditionalAuthenticatedData(associatedData)
            .setAdditionalAuthenticatedDataCrc32c(invalidCrc);

    // TODO(ckl): Add CRC validation to FakeCloudKms. This should throw.
    EncryptResponse encResponse2 =
        kms.projects()
            .locations()
            .keyRings()
            .cryptoKeys()
            .encrypt(KEY_ID, encRequestWithInvalidAssociatedDataCrc)
            .execute();
    assertThat(encResponse2).isNotNull();
  }

  @Test
  public void testDecrytWithInvalidCrc_successBecauseCrcIsNotVerified() throws Exception {
    CloudKMS kms = new FakeCloudKms(asList(KEY_ID));

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    Long invalidCrc = Long.valueOf(123);

    // get valid ciphertext
    EncryptRequest encRequest =
        new EncryptRequest()
            .encodePlaintext(plaintext)
            .encodeAdditionalAuthenticatedData(associatedData);
    EncryptResponse encResponse =
        kms.projects().locations().keyRings().cryptoKeys().encrypt(KEY_ID, encRequest).execute();
    byte[] ciphertext = encResponse.decodeCiphertext();

    DecryptRequest decRequestWithInvalidCiphertextCrc =
        new DecryptRequest()
            .encodeCiphertext(ciphertext)
            .setCiphertextCrc32c(invalidCrc)
            .encodeAdditionalAuthenticatedData(associatedData);

    // TODO(ckl): Add CRC validation to FakeCloudKms. This should throw.
    DecryptResponse decResponse =
        kms.projects()
            .locations()
            .keyRings()
            .cryptoKeys()
            .decrypt(KEY_ID, decRequestWithInvalidCiphertextCrc)
            .execute();
    assertThat(decResponse).isNotNull();

    DecryptRequest decRequestWithInvalidAssociatedDataCrc =
        new DecryptRequest()
            .encodeCiphertext(ciphertext)
            .encodeAdditionalAuthenticatedData(associatedData)
            .setAdditionalAuthenticatedDataCrc32c(invalidCrc);

    // TODO(ckl): Add CRC validation to FakeCloudKms. This should throw.
    DecryptResponse decResponse2 =
        kms.projects()
            .locations()
            .keyRings()
            .cryptoKeys()
            .decrypt(KEY_ID, decRequestWithInvalidAssociatedDataCrc)
            .execute();
    assertThat(decResponse2).isNotNull();
  }

  @Test
  public void testEncryptDecryptWithoutAssociatedData() throws Exception {
    CloudKMS kms = new FakeCloudKms(asList(KEY_ID));

    byte[] plaintext = "plaintext".getBytes(UTF_8);

    EncryptRequest encRequest = new EncryptRequest().encodePlaintext(plaintext);

    EncryptResponse encResponse =
        kms.projects().locations().keyRings().cryptoKeys().encrypt(KEY_ID, encRequest).execute();

    DecryptRequest decRequest =
        new DecryptRequest().encodeCiphertext(encResponse.decodeCiphertext());

    DecryptResponse decResponse =
        kms.projects().locations().keyRings().cryptoKeys().decrypt(KEY_ID, decRequest).execute();

    assertThat(decResponse.decodePlaintext()).isEqualTo(plaintext);

    // Empty associated data is the same as no associated data.
    DecryptRequest decRequestWithEmptyAssociatedData =
        new DecryptRequest()
            .encodeCiphertext(encResponse.decodeCiphertext())
            .encodeAdditionalAuthenticatedData(new byte[0]);

    DecryptResponse decResponseWithEmptyAssociatedData =
        kms.projects()
            .locations()
            .keyRings()
            .cryptoKeys()
            .decrypt(KEY_ID, decRequestWithEmptyAssociatedData)
            .execute();
    assertThat(decResponseWithEmptyAssociatedData.decodePlaintext()).isEqualTo(plaintext);

    // A non-empty associated data is no valid for a request without associated data.
    DecryptRequest decRequestWithInvalidAssociatedData =
        new DecryptRequest()
            .encodeCiphertext(encResponse.decodeCiphertext())
            .encodeAdditionalAuthenticatedData("invalidAssociatedData".getBytes(UTF_8));

    CloudKMS.Projects.Locations.KeyRings.CryptoKeys.Decrypt dec =
        kms.projects()
            .locations()
            .keyRings()
            .cryptoKeys()
            .decrypt(KEY_ID, decRequestWithInvalidAssociatedData);
    assertThrows(IOException.class, dec::execute);
  }

  @Test
  public void encryptEmptyData_decryptReturnsNull() throws Exception {
    CloudKMS kms = new FakeCloudKms(asList(KEY_ID));

    byte[] plaintext = "".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    EncryptRequest encRequest =
        new EncryptRequest()
            .encodePlaintext(plaintext)
            .encodeAdditionalAuthenticatedData(associatedData);

    EncryptResponse encResponse =
        kms.projects().locations().keyRings().cryptoKeys().encrypt(KEY_ID, encRequest).execute();

    DecryptRequest decRequest =
        new DecryptRequest()
            .encodeCiphertext(encResponse.decodeCiphertext())
            .encodeAdditionalAuthenticatedData(associatedData);

    DecryptResponse decResponse =
        kms.projects().locations().keyRings().cryptoKeys().decrypt(KEY_ID, decRequest).execute();

    assertThat(decResponse.decodePlaintext()).isNull();
  }

  @Test
  public void testEncryptWithUnknownKeyId_executeFails() throws Exception {
    CloudKMS kms = new FakeCloudKms(asList(KEY_ID));

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    EncryptRequest encRequest =
        new EncryptRequest()
            .encodePlaintext(plaintext)
            .encodeAdditionalAuthenticatedData(associatedData);

    // The RPC to the KMS is done when execute is called. Therefore, calling encrypt for a
    // valid but unknown key id does not (yet) fail.
    CloudKMS.Projects.Locations.KeyRings.CryptoKeys.Encrypt enc =
        kms.projects().locations().keyRings().cryptoKeys().encrypt(KEY_ID_2, encRequest);
    assertThrows(IOException.class, enc::execute);
  }

  @Test
  public void testEncryptWithInvalidKeyId_encryptFails() throws Exception {
    String invalidId = "invalid";

    CloudKMS kms = new FakeCloudKms(asList(invalidId));

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    EncryptRequest encRequest =
        new EncryptRequest()
            .encodePlaintext(plaintext)
            .encodeAdditionalAuthenticatedData(associatedData);

    // Encrypts validates the format of the key id, and fails if it is invalid.
    CloudKMS.Projects.Locations.KeyRings.CryptoKeys cryptoKeys =
        kms.projects().locations().keyRings().cryptoKeys();
    assertThrows(IllegalArgumentException.class, () -> cryptoKeys.encrypt(invalidId, encRequest));
  }

  @Test
  public void testDecryptWithInvalidKeyId_decryptFails() throws Exception {
    String invalidId = "invalid";

    CloudKMS kms = new FakeCloudKms(asList(KEY_ID, invalidId));

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    EncryptRequest encRequest =
        new EncryptRequest()
            .encodePlaintext(plaintext)
            .encodeAdditionalAuthenticatedData(associatedData);

    EncryptResponse encResponse =
        kms.projects().locations().keyRings().cryptoKeys().encrypt(KEY_ID, encRequest).execute();

    DecryptRequest decRequest =
        new DecryptRequest()
            .encodeCiphertext(encResponse.decodeCiphertext())
            .encodeAdditionalAuthenticatedData(associatedData);

    // Decrypt validates the format of the key id, and fails if it is invalid.
    CloudKMS.Projects.Locations.KeyRings.CryptoKeys cryptoKeys =
        kms.projects().locations().keyRings().cryptoKeys();
    assertThrows(IllegalArgumentException.class, () -> cryptoKeys.decrypt(invalidId, decRequest));
  }


  @Test
  public void testDecryptWithWrongKeyId_decryptFails() throws Exception {
    CloudKMS kms = new FakeCloudKms(asList(KEY_ID, KEY_ID_2));

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    EncryptRequest encRequest =
        new EncryptRequest()
            .encodePlaintext(plaintext)
            .encodeAdditionalAuthenticatedData(associatedData);

    EncryptResponse encResponse =
        kms.projects().locations().keyRings().cryptoKeys().encrypt(KEY_ID, encRequest).execute();

    DecryptRequest decRequest =
        new DecryptRequest()
            .encodeCiphertext(encResponse.decodeCiphertext())
            .encodeAdditionalAuthenticatedData(associatedData);

    // The RPC to the KMS is done when execute is called. Therefore, calling decrypt with a wrong
    // key id does not (yet) fail.
    CloudKMS.Projects.Locations.KeyRings.CryptoKeys.Decrypt dec =
        kms.projects()
            .locations()
            .keyRings()
            .cryptoKeys()
            .decrypt(KEY_ID_2, decRequest);
    assertThrows(IOException.class, dec::execute);
  }

  @Test
  public void testDecryptExecuteWithInvalidCiphertext_executeFails() throws Exception {
    CloudKMS kms = new FakeCloudKms(asList(KEY_ID));

    byte[] invalidCiphertext = "invalid".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    DecryptRequest decRequestWithInvalidCiphertext =
        new DecryptRequest()
            .encodeCiphertext(invalidCiphertext)
            .encodeAdditionalAuthenticatedData(associatedData);

    CloudKMS.Projects.Locations.KeyRings.CryptoKeys.Decrypt dec =
        kms.projects()
            .locations()
            .keyRings()
            .cryptoKeys()
            .decrypt(KEY_ID, decRequestWithInvalidCiphertext);
    assertThrows(IOException.class, dec::execute);
  }

  @Test
  public void testEncryptDecryptWithTwoValidKeyId_success() throws Exception {
    CloudKMS kms = new FakeCloudKms(asList(KEY_ID, KEY_ID_2));

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] plaintext2 = "plaintext2".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    EncryptRequest encRequest =
        new EncryptRequest()
            .encodePlaintext(plaintext)
            .encodeAdditionalAuthenticatedData(associatedData);
    EncryptResponse encResponse =
        kms.projects().locations().keyRings().cryptoKeys().encrypt(KEY_ID, encRequest).execute();

    EncryptRequest encRequest2 =
        new EncryptRequest()
            .encodePlaintext(plaintext2)
            .encodeAdditionalAuthenticatedData(associatedData);

    EncryptResponse encResponse2 =
        kms.projects().locations().keyRings().cryptoKeys().encrypt(KEY_ID, encRequest2).execute();

    DecryptRequest decRequest =
        new DecryptRequest()
            .encodeCiphertext(encResponse.decodeCiphertext())
            .encodeAdditionalAuthenticatedData(associatedData);

    DecryptResponse decResponse =
        kms.projects().locations().keyRings().cryptoKeys().decrypt(KEY_ID, decRequest).execute();

    assertThat(decResponse.decodePlaintext()).isEqualTo(plaintext);

    DecryptRequest decRequest2 =
        new DecryptRequest()
            .encodeCiphertext(encResponse2.decodeCiphertext())
            .encodeAdditionalAuthenticatedData(associatedData);

    DecryptResponse decResponse2 =
        kms.projects().locations().keyRings().cryptoKeys().decrypt(KEY_ID, decRequest2).execute();

    assertThat(decResponse2.decodePlaintext()).isEqualTo(plaintext2);
  }
}
