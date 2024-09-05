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

import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.LowLevelHttpRequest;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.services.cloudkms.v1.CloudKMS;
import com.google.api.services.cloudkms.v1.model.DecryptRequest;
import com.google.api.services.cloudkms.v1.model.DecryptResponse;
import com.google.api.services.cloudkms.v1.model.EncryptRequest;
import com.google.api.services.cloudkms.v1.model.EncryptResponse;
import com.google.common.hash.Hashing;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * A partial, fake implementation of {@link com.google.api.services.cloudkms.v1.CloudKMS}.
 *
 * <p>It creates a new AEAD for every valid key ID. CryptoKeys use them to encrypt and decrypt.
 */
final class FakeCloudKms extends CloudKMS {
  private final Map<String, Aead> aeads = new HashMap<>();

  public FakeCloudKms(List<String> validKeyIds)
      throws GeneralSecurityException {
    super(
        new HttpTransport() {
          @Override
          protected LowLevelHttpRequest buildRequest(String method, String url) throws IOException {
            throw new IOException("Test should not have interacted with HttpTransport.");
          }
        },
        new GsonFactory(),
        new GoogleCredential());
    for (String keyId : validKeyIds) {
      Aead aead =
          KeysetHandle.generateNew(KeyTemplates.get("AES128_GCM"))
              .getPrimitive(RegistryConfiguration.get(), Aead.class);
      aeads.put(keyId, aead);
    }
  }

  private final Projects projects = new Projects();

  @Override
  public Projects projects() {
    return projects;
  }

  final class Projects extends CloudKMS.Projects {

    private final Locations locations = new Locations();

    @Override
    public Locations locations() {
      return locations;
    }

    final class Locations extends CloudKMS.Projects.Locations {

      private final KeyRings keyRings = new KeyRings();

      @Override
      public KeyRings keyRings() {
        return keyRings;
      }

      final class KeyRings extends CloudKMS.Projects.Locations.KeyRings {

        private final CryptoKeys cryptoKeys = new CryptoKeys();

        @Override
        public CryptoKeys cryptoKeys() {
          return cryptoKeys;
        }

        final class CryptoKeys extends CloudKMS.Projects.Locations.KeyRings.CryptoKeys {
          @Override
          public Encrypt encrypt(String name, EncryptRequest request) {
            return new Encrypt(name, request);
          }

          @Override
          public Decrypt decrypt(String name, DecryptRequest request) {
            return new Decrypt(name, request);
          }

          final class Encrypt extends CloudKMS.Projects.Locations.KeyRings.CryptoKeys.Encrypt {
            String name;
            EncryptRequest request;

            Encrypt(String name, EncryptRequest request) {
              super(name, request);
              this.name = name;
              this.request = request;
            }

            @Override
            public EncryptResponse execute() throws IOException {
              if (!aeads.containsKey(name)) {
                throw new IOException(
                    "Unknown key ID : " + name + " is not in " + aeads.keySet());
              }

              EncryptResponse response = new EncryptResponse().setName(this.name);

              byte[] plaintext = request.decodePlaintext();
              try {
                if (validateCrc32c(plaintext, request.getPlaintextCrc32c())) {
                  response.setVerifiedPlaintextCrc32c(true);
                }
              } catch (IOException e) {
                throw new IOException("Invalid argument, plaintext " + e.getMessage());
              }

              byte[] associatedData = request.decodeAdditionalAuthenticatedData();
              try {
                if (validateCrc32c(
                    associatedData, request.getAdditionalAuthenticatedDataCrc32c())) {
                  response.setVerifiedAdditionalAuthenticatedDataCrc32c(true);
                }
              } catch (IOException e) {
                throw new IOException(
                    "Invalid argument, additional authenticated data " + e.getMessage());
              }

              try {
                Aead aead = aeads.get(name);
                byte[] ciphertext = aead.encrypt(plaintext, associatedData);
                long ciphertextCrc32c = Hashing.crc32c().hashBytes(ciphertext).padToLong();

                return response.encodeCiphertext(ciphertext).setCiphertextCrc32c(ciphertextCrc32c);
              } catch (GeneralSecurityException e) {
                throw new IOException(e.getMessage());
              }
            }
          }

          final class Decrypt extends CloudKMS.Projects.Locations.KeyRings.CryptoKeys.Decrypt {
            String name;
            DecryptRequest request;

            Decrypt(String name, DecryptRequest request) {
              super(name, request);
              this.name = name;
              this.request = request;
            }

            @Override
            public DecryptResponse execute() throws IOException {
              if (!aeads.containsKey(name)) {
                throw new IOException("Unknown key ID : " + name + " is not in " + aeads.keySet());
              }
              try {
                Aead aead = aeads.get(name);

                byte[] ciphertext = request.decodeCiphertext();
                try {
                  validateCrc32c(ciphertext, request.getCiphertextCrc32c());
                } catch (IOException e) {
                  throw new IOException("Invalid argument, ciphertext " + e.getMessage());
                }

                byte[] associatedData = request.decodeAdditionalAuthenticatedData();
                try {
                  validateCrc32c(associatedData, request.getAdditionalAuthenticatedDataCrc32c());
                } catch (IOException e) {
                  throw new IOException("Invalid argument, associatedData " + e.getMessage());
                }

                byte[] plaintext = aead.decrypt(ciphertext, associatedData);
                long plaintextCrc32c = Hashing.crc32c().hashBytes(plaintext).padToLong();

                DecryptResponse response = new DecryptResponse();

                if (plaintext.length == 0) {
                  // The real CloudKMS also returns null in this case.
                  response.encodePlaintext(null);
                } else {
                  response.encodePlaintext(plaintext);
                }

                return response.setPlaintextCrc32c(plaintextCrc32c);
              } catch (GeneralSecurityException e) {
                throw new IOException(e.getMessage());
              }
            }
          }
        }
      }
    }
  }

  // Returns true if validation succeeded, false if validation skipped, throws if validation failed.
  @CanIgnoreReturnValue
  private static boolean validateCrc32c(byte[] input, Long expectedCrc32c) throws IOException {
    if (input == null || expectedCrc32c == null) {
      return false;
    }
    long inputCrc32c = Hashing.crc32c().hashBytes(input).padToLong();
    if (inputCrc32c != expectedCrc32c) {
      throw new IOException("CRC mismatch");
    }
    return true;
  }
}
