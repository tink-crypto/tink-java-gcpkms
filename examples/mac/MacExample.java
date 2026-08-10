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
// [START mac-example]
package mac;

import com.google.api.gax.core.FixedCredentialsProvider;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.KeyManagementServiceSettings;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.integration.gcpkms.GcpKmsMac;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;

/**
 * A command-line utility for computing and verifying message authentication codes (MACs) with a
 * Google Cloud KMS MAC key.
 *
 * <p>It requires the following arguments:
 *
 * <ul>
 *   <li>mode: Can be "compute" or "verify" to compute a MAC over the input or verify one.
 *   <li>key-name: Resource name of the Cloud KMS CryptoKeyVersion to use, in the format {@code
 *       projects/<my-project>/locations/global/keyRings/<my-key-ring>/cryptoKeys/<my-key>/cryptoKeyVersions/<my-version>}.
 *   <li>gcp-credential-file: Use this JSON credential file to connect to Cloud KMS.
 *   <li>input-file: Read the message to authenticate or verify from this file.
 *   <li>mac-file: Written by "compute", read by "verify".
 * </ul>
 */
public final class MacExample {
  private static final String MODE_COMPUTE = "compute";
  private static final String MODE_VERIFY = "verify";

  public static void main(String[] args) throws Exception {
    if (args.length != 5) {
      System.err.printf("Expected 5 parameters, got %d\n", args.length);
      System.err.println(
          "Usage: java MacExample compute/verify key-name gcp-credential-file"
              + " input-file mac-file");
      System.exit(1);
    }
    String mode = args[0];
    String keyName = args[1];
    String gcpCredentialFilename = args[2];
    byte[] message = Files.readAllBytes(Path.of(args[3]));
    File macFile = new File(args[4]);

    if (!mode.equals(MODE_COMPUTE) && !mode.equals(MODE_VERIFY)) {
      System.err.println("The first argument must be either compute or verify, got: " + mode);
      System.exit(1);
    }

    // Cloud KMS is contacted through a gRPC client that is authenticated with the given service
    // account credentials.
    try (KeyManagementServiceClient kmsClient = createKmsClient(gcpCredentialFilename)) {
      // Cloud KMS acts as a crypto oracle: both computing and verifying the MAC send the message
      // to Cloud KMS; the key never leaves Cloud KMS.
      Mac mac =
          GcpKmsMac.builder().setKeyName(keyName).setKeyManagementServiceClient(kmsClient).build();

      if (mode.equals(MODE_COMPUTE)) {
        byte[] tag = mac.computeMac(message);
        try (FileOutputStream stream = new FileOutputStream(macFile)) {
          stream.write(tag);
        }
      } else {
        byte[] tag = Files.readAllBytes(macFile.toPath());
        try {
          mac.verifyMac(tag, message);
        } catch (GeneralSecurityException ex) {
          System.err.println("MAC verification failed: " + ex);
          System.exit(1);
        }
      }
    }

    System.exit(0);
  }

  /** Creates a Cloud KMS client that authenticates with the given service account credentials. */
  private static KeyManagementServiceClient createKmsClient(String gcpCredentialFilename)
      throws Exception {
    GoogleCredentials credentials;
    try (InputStream stream = new FileInputStream(gcpCredentialFilename)) {
      credentials =
          GoogleCredentials.fromStream(stream)
              .createScoped("https://www.googleapis.com/auth/cloud-platform");
    }
    return KeyManagementServiceClient.create(
        KeyManagementServiceSettings.newBuilder()
            .setCredentialsProvider(FixedCredentialsProvider.create(credentials))
            .build());
  }

  private MacExample() {}
}
// [END mac-example]
