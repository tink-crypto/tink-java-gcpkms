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
// [START signature-example]
package signature;

import com.google.api.gax.core.FixedCredentialsProvider;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.cloud.kms.v1.CryptoKeyVersion.CryptoKeyVersionAlgorithm;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.KeyManagementServiceSettings;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.integration.gcpkms.GcpKmsPublicKeySign;
import com.google.crypto.tink.integration.gcpkms.GcpKmsPublicKeyVerify;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;

/**
 * A command-line utility for signing and verifying files with a Google Cloud KMS asymmetric key.
 *
 * <p>It requires the following arguments:
 *
 * <ul>
 *   <li>mode: Can be "sign", "verify", or "verify-offline".
 *   <li>key-name: Resource name of the Cloud KMS CryptoKeyVersion to use, in the format {@code
 *       projects/<my-project>/locations/global/keyRings/<my-key-ring>/cryptoKeys/<my-key>/cryptoKeyVersions/<my-version>}.
 *       Can be empty ("") when mode is "verify-offline".
 *   <li>gcp-credential-file: Use this JSON credential file to connect to Cloud KMS. Can be empty
 *       ("") when mode is "verify-offline".
 *   <li>input-file: Read the message to sign or verify from this file.
 *   <li>signature-file: Written by "sign", read by "verify" and "verify-offline".
 *   <li>[optional] public-key-file: (Required for "verify-offline") Read the pre-fetched public key
 *       from this file.
 *   <li>[optional] algorithm: (Required for "verify-offline") The Cloud KMS
 *       CryptoKeyVersionAlgorithm (e.g., EC_SIGN_P256_SHA256).
 * </ul>
 */
public final class SignatureExample {
  private static final String MODE_SIGN = "sign";
  private static final String MODE_VERIFY = "verify";
  private static final String MODE_VERIFY_OFFLINE = "verify-offline";

  public static void main(String[] args) throws Exception {
    if (args.length != 5 && args.length != 7) {
      System.err.printf("Expected 5 or 7 parameters, got %d\n", args.length);
      System.err.println(
          "Usage: java SignatureExample sign/verify/verify-offline key-name gcp-credential-file"
              + " input-file signature-file [public-key-file algorithm]");
      System.exit(1);
    }
    String mode = args[0];
    byte[] message = Files.readAllBytes(Paths.get(args[3]));
    File signatureFile = new File(args[4]);

    if (!mode.equals(MODE_SIGN)
        && !mode.equals(MODE_VERIFY)
        && !mode.equals(MODE_VERIFY_OFFLINE)) {
      System.err.println(
          "The first argument must be either sign, verify, or verify-offline, got: " + mode);
      System.exit(1);
    }

    if (mode.equals(MODE_VERIFY_OFFLINE)) {
      if (args.length != 7) {
        System.err.println("verify-offline mode requires 7 parameters.");
        System.exit(1);
      }
      // Offline verification uses a pre-fetched public key and algorithm name; no Cloud KMS calls
      // are made and no credentials are required.
      byte[] publicKey = Files.readAllBytes(Paths.get(args[5]));
      CryptoKeyVersionAlgorithm algorithm = CryptoKeyVersionAlgorithm.valueOf(args[6]);
      byte[] signature = Files.readAllBytes(signatureFile.toPath());
      PublicKeyVerify verifier =
          GcpKmsPublicKeyVerify.builder().setPublicKey(publicKey).setAlgorithm(algorithm).build();
      try {
        verifier.verify(signature, message);
      } catch (GeneralSecurityException ex) {
        System.err.println("Signature verification failed: " + ex);
        System.exit(1);
      }
    } else {
      if (args.length != 5) {
        System.err.println(mode + " mode requires 5 parameters.");
        System.exit(1);
      }
      String keyName = args[1];
      String gcpCredentialFilename = args[2];
      // Cloud KMS is contacted through a gRPC client that is authenticated with the given service
      // account credentials.
      try (KeyManagementServiceClient kmsClient = createKmsClient(gcpCredentialFilename)) {
        if (mode.equals(MODE_SIGN)) {
          // The signer sends the message (or, for some algorithms, only its digest) to Cloud KMS
          // for each sign call; the private key never leaves Cloud KMS.
          PublicKeySign signer =
              GcpKmsPublicKeySign.builder()
                  .setKeyName(keyName)
                  .setKeyManagementServiceClient(kmsClient)
                  .build();
          byte[] signature = signer.sign(message);
          try (FileOutputStream stream = new FileOutputStream(signatureFile)) {
            stream.write(signature);
          }
        } else {
          // The verifier fetches the public key from Cloud KMS once, and then verifies locally; no
          // per-operation Cloud KMS calls are made.
          byte[] signature = Files.readAllBytes(signatureFile.toPath());
          PublicKeyVerify verifier =
              GcpKmsPublicKeyVerify.builder()
                  .setKeyName(keyName)
                  .setKeyManagementServiceClient(kmsClient)
                  .build();
          try {
            verifier.verify(signature, message);
          } catch (GeneralSecurityException ex) {
            System.err.println("Signature verification failed: " + ex);
            System.exit(1);
          }
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

  private SignatureExample() {}
}
// [END signature-example]
