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
import com.google.cloud.kms.v1.PublicKey;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.integration.gcpkms.internal.GcpKmsUtil;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.util.Arrays;
import java.util.List;
import org.conscrypt.Conscrypt;
import org.junit.AfterClass;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

/**
 * Integration tests for {@link GcpKmsPublicKeySign} and {@link GcpKmsPublicKeyVerify} with the real
 * GCP Cloud KMS.
 */
@RunWith(Parameterized.class)
public final class GcpKmsSignatureIntegrationTest {

  // This integration test can be successfully executed when this file contains credentials for a
  // service account which has access to the keys in {@link #KEY_VERSION_NAME_PREFIX}.
  private static final String GCP_CREDENTIALS_FILE =
      "testdata/gcp/credential.json";

  // KMS key ring hosted in the Google Cloud project `tink-test-infrastructure`, used for Tink
  // integration tests.
  private static final String KEY_VERSION_NAME_PREFIX =
      "projects/tink-test-infrastructure/locations/global/keyRings/"
          + "unit-and-integration-testing/cryptoKeys/";

  // Maximum size of the data that GcpKmsPublicKeySign sends to Cloud KMS. Kept in sync with
  // GcpKmsPublicKeySign.MAX_SIGN_DATA_SIZE, which is private.
  private static final int MAX_SIGN_DATA_SIZE = 64 * 1024;

  private static final byte[] data = "This is some message to sign.".getBytes(UTF_8);
  private static final byte[] otherData = "This is some other message.".getBytes(UTF_8);

  /** A Cloud KMS asymmetric-sign key to test, together with how Tink uses it. */
  private static final class SignatureKeyTestCase {
    /** Name of the CryptoKey, used to build the JUnit test names. */
    final String cryptoKey;

    /** Resource name of version 1 of {@link #cryptoKey}. */
    final String keyVersionName;

    /**
     * Whether Cloud KMS signs the message itself rather than a digest of it, in which case the
     * client-side {@link #MAX_SIGN_DATA_SIZE} limit applies.
     */
    final boolean requiresDataForSign;

    SignatureKeyTestCase(String cryptoKey, boolean requiresDataForSign) {
      this.cryptoKey = cryptoKey;
      // Asymmetric signing is bound to a specific CryptoKeyVersion, so the version is part of the
      // name.
      this.keyVersionName = KEY_VERSION_NAME_PREFIX + cryptoKey + "/cryptoKeyVersions/1";
      this.requiresDataForSign = requiresDataForSign;
    }

    boolean isSupported() {
      if (cryptoKey.startsWith("ml-dsa")) {
        return isAlgorithmSupported("ML-DSA-65");
      }
      if (cryptoKey.startsWith("slh-dsa")) {
        return isAlgorithmSupported("SLH-DSA-SHA2-128s");
      }
      return true;
    }

    @Override
    public String toString() {
      return cryptoKey;
    }
  }

  @Parameters(name = "{0}")
  public static List<SignatureKeyTestCase> signatureKeys() {
    return Arrays.asList(
        new SignatureKeyTestCase("signature-key", /* requiresDataForSign= */ false),
        new SignatureKeyTestCase("rsa-pss-2048-key", /* requiresDataForSign= */ false),
        new SignatureKeyTestCase("ml-dsa-65-key", /* requiresDataForSign= */ true),
        new SignatureKeyTestCase("ml-dsa-65-external-mu-key", /* requiresDataForSign= */ false),
        new SignatureKeyTestCase("slh-dsa-128s-key", /* requiresDataForSign= */ true));
  }

  private static KeyManagementServiceClient kmsClient;

  private final SignatureKeyTestCase testCase;

  public GcpKmsSignatureIntegrationTest(SignatureKeyTestCase testCase) {
    this.testCase = testCase;
  }

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
    // ML-DSA and SLH-DSA verification is delegated to Conscrypt, which must be installed as a JCA
    // provider. The classical algorithms do not need it, so it is only installed when available;
    // post-quantum test cases will skip if it is missing.
    if (Conscrypt.isAvailable()) {
      Security.addProvider(Conscrypt.newProvider());
    }
    kmsClient = createKmsClient(GCP_CREDENTIALS_FILE);
  }

  @AfterClass
  public static void tearDownClass() {
    if (kmsClient != null) {
      kmsClient.close();
    }
  }

  /** Returns whether the installed Conscrypt provider supports the given algorithm. */
  private static boolean isAlgorithmSupported(String algorithm) {
    Provider provider = Security.getProvider("Conscrypt");
    if (provider == null) {
      return false;
    }
    try {
      Signature unused = Signature.getInstance(algorithm, provider);
      return true;
    } catch (GeneralSecurityException e) {
      return false;
    }
  }

  /** Returns a signer that signs with the Cloud KMS key under test. */
  private PublicKeySign signer() throws Exception {
    return GcpKmsPublicKeySign.builder()
        .setKeyName(testCase.keyVersionName)
        .setKeyManagementServiceClient(kmsClient)
        .build();
  }

  /** Returns a verifier built from the public key that Cloud KMS serves for the key under test. */
  private PublicKeyVerify verifier() throws Exception {
    return GcpKmsPublicKeyVerify.builder()
        .setKeyName(testCase.keyVersionName)
        .setKeyManagementServiceClient(kmsClient)
        .build();
  }

  @Test
  public void signAndVerify_success() throws Exception {
    Assume.assumeTrue(testCase.isSupported());
    byte[] signature = signer().sign(data);

    verifier().verify(signature, data); // Must not throw.
  }

  @Test
  public void verify_modifiedMessage_fails() throws Exception {
    Assume.assumeTrue(testCase.isSupported());
    byte[] signature = signer().sign(data);
    PublicKeyVerify verifier = verifier();

    var e =
        assertThrows(GeneralSecurityException.class, () -> verifier.verify(signature, otherData));
    assertThat(e).hasMessageThat().contains("invalid signature");
  }

  @Test
  public void verify_modifiedSignature_fails() throws Exception {
    Assume.assumeTrue(testCase.isSupported());
    byte[] signature = signer().sign(data);
    assertThat(signature).isNotEmpty();

    byte[] modifiedSignature = Arrays.copyOf(signature, signature.length);
    modifiedSignature[modifiedSignature.length - 1] ^= (byte) 0x01;
    PublicKeyVerify verifier = verifier();

    var e =
        assertThrows(
            GeneralSecurityException.class, () -> verifier.verify(modifiedSignature, data));
    assertThat(e).hasMessageThat().contains("invalid signature");
  }

  @Test
  public void verify_truncatedSignature_fails() throws Exception {
    Assume.assumeTrue(testCase.isSupported());
    byte[] signature = signer().sign(data);
    assertThat(signature).isNotEmpty();

    byte[] truncatedSignature = Arrays.copyOf(signature, signature.length - 1);
    PublicKeyVerify verifier = verifier();

    var e =
        assertThrows(
            GeneralSecurityException.class, () -> verifier.verify(truncatedSignature, data));
    assertThat(e).hasMessageThat().contains("invalid signature");
  }

  @Test
  public void verify_offline() throws Exception {
    Assume.assumeTrue(testCase.isSupported());
    byte[] signature = signer().sign(data);

    // Fetch the public key material, then build a verifier from it without further calls to Cloud
    // KMS.
    PublicKey kmsPublicKey = GcpKmsUtil.fetchPublicKey(kmsClient, testCase.keyVersionName);
    PublicKeyVerify verifier =
        GcpKmsPublicKeyVerify.builder()
            .setPublicKey(kmsPublicKey.getPublicKey().getData().toByteArray())
            .setAlgorithm(kmsPublicKey.getAlgorithm())
            .build();

    verifier.verify(signature, data); // Must not throw.

    // Verify that verification fails for invalid data.
    var e =
        assertThrows(GeneralSecurityException.class, () -> verifier.verify(signature, otherData));
    assertThat(e).hasMessageThat().contains("invalid signature");
  }

  @Test
  public void signAndVerify_maxDataSize_success() throws Exception {
    Assume.assumeTrue(testCase.isSupported());
    // Only the algorithms that send the message itself to Cloud KMS are subject to the client-side
    // size limit; the ones that sign a digest are not.
    Assume.assumeTrue(testCase.requiresDataForSign);

    byte[] maxData = new byte[MAX_SIGN_DATA_SIZE];
    Arrays.fill(maxData, (byte) 'a');

    byte[] signature = signer().sign(maxData);

    verifier().verify(signature, maxData); // Must not throw.
  }

  @Test
  public void signAndVerify_beyondMaxDataSize_success() throws Exception {
    Assume.assumeTrue(testCase.isSupported());
    // Algorithms that do not require data for sign (e.g. they compute a digest or message
    // representative locally like External MU) are not subject to the client-side size limit.
    Assume.assumeFalse(testCase.requiresDataForSign);

    byte[] largeData = new byte[MAX_SIGN_DATA_SIZE + 1024];
    Arrays.fill(largeData, (byte) 'a');

    byte[] signature = signer().sign(largeData);

    verifier().verify(signature, largeData); // Must not throw.
  }
}
