// Copyright 2026 Google Inc.
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

import com.google.api.gax.core.FixedCredentialsProvider;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.KeyManagementServiceSettings;
import com.google.crypto.tink.Mac;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Integration tests for {@link GcpKmsMac} with the real GCP Cloud KMS. */
@RunWith(JUnit4.class)
public final class GcpKmsMacIntegrationTest {

  // This integration test can be successfully executed when this file contains credentials for a
  // service account which has access to the key specified in {@link #MAC_KEY_NAME}.
  private static final String GCP_CREDENTIALS_FILE =
      "testdata/gcp/credential.json";

  // An HMAC-SHA256 CryptoKeyVersion. Unlike an AEAD key URI, MAC operations are bound to a specific
  // CryptoKeyVersion, so the name includes the version.
  private static final String MAC_KEY_NAME =
      "projects/tink-test-infrastructure/locations/global/keyRings/"
          + "unit-and-integration-testing/cryptoKeys/mac-key/cryptoKeyVersions/1";

  private static final byte[] data = "This is some data to authenticate.".getBytes(UTF_8);
  private static final byte[] otherData = "This is some other data.".getBytes(UTF_8);

  private static KeyManagementServiceClient kmsClient;
  private static Mac mac;

  /** Creates a Cloud KMS client that authenticates with the given service account credentials. */
  private static KeyManagementServiceClient createKmsClient(String credentialsFile)
      throws Exception {
    GoogleCredentials credentials;
    try (InputStream stream = new FileInputStream(credentialsFile)) {
      credentials =
          GoogleCredentials.fromStream(stream)
              .createScoped("https://www.googleapis.com/auth/cloud-platform");
    }
    return KeyManagementServiceClient.create(
        KeyManagementServiceSettings.newBuilder()
            .setCredentialsProvider(FixedCredentialsProvider.create(credentials))
            .build());
  }

  @BeforeClass
  public static void setUpClass() throws Exception {
    kmsClient = createKmsClient(GCP_CREDENTIALS_FILE);
    mac =
        GcpKmsMac.builder()
            .setKeyName(MAC_KEY_NAME)
            .setKeyManagementServiceClient(kmsClient)
            .build();
  }

  @AfterClass
  public static void tearDownClass() {
    if (kmsClient != null) {
      kmsClient.close();
    }
  }

  @Test
  public void computeAndVerifyMac_success() throws Exception {
    byte[] tag = mac.computeMac(data);
    mac.verifyMac(tag, data); // Must not throw.
  }

  @Test
  public void computeMac_isDeterministic() throws Exception {
    // HMAC is deterministic, and both calls are pinned to the same CryptoKeyVersion, so the two
    // tags must be identical.
    byte[] tag = mac.computeMac(data);
    byte[] sameTag = mac.computeMac(data);
    assertThat(sameTag).isEqualTo(tag);
  }

  @Test
  public void verifyMac_wrongData_fails() throws Exception {
    byte[] tag = mac.computeMac(data);
    GeneralSecurityException e =
        assertThrows(GeneralSecurityException.class, () -> mac.verifyMac(tag, otherData));
    // Cloud KMS reports that the MAC does not match, rather than failing the RPC.
    assertThat(e).hasMessageThat().contains("MAC verification failed.");
  }

  @Test
  public void verifyMac_modifiedMac_fails() throws Exception {
    byte[] tag = mac.computeMac(data);
    assertThat(tag).isNotEmpty();

    // Only flip a bit, so that the MAC keeps the length Cloud KMS expects.
    tag[0] ^= (byte) 0x01;
    GeneralSecurityException e =
        assertThrows(GeneralSecurityException.class, () -> mac.verifyMac(tag, data));
    assertThat(e).hasMessageThat().contains("MAC verification failed.");
  }

  @Test
  public void computeAndVerifyMac_maxDataSize_success() throws Exception {
    byte[] maxData = new byte[GcpKmsMac.MAX_MAC_DATA_SIZE];
    Arrays.fill(maxData, (byte) 'a');
    byte[] tag = mac.computeMac(maxData);
    mac.verifyMac(tag, maxData); // Must not throw.
  }

  @Test
  public void verifyMac_truncatedTag_fails() throws Exception {
    byte[] tag = mac.computeMac(data);
    assertThat(tag).isNotEmpty();
    byte[] truncatedTag = Arrays.copyOf(tag, tag.length - 1);
    GeneralSecurityException e =
        assertThrows(GeneralSecurityException.class, () -> mac.verifyMac(truncatedTag, data));
    assertThat(e).hasMessageThat().contains("GCP KMS MacVerify failed.");
  }
}
