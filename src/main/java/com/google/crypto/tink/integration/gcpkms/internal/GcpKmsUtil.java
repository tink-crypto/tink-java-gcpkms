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

import com.google.cloud.kms.v1.PublicKey;
import com.google.common.hash.Hashing;
import java.security.GeneralSecurityException;
import java.util.regex.Pattern;

/** Helper functions shared by the Google Cloud KMS integration, for internal use only. */
public final class GcpKmsUtil {

  private static final String KEY_NAME_PATTERN =
      "projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+/cryptoKeyVersions/.*";
  private static final Pattern KEY_NAME_MATCHER = Pattern.compile(KEY_NAME_PATTERN);

  /**
   * Validates that {@code keyName} is a well-formed Cloud KMS CryptoKeyVersion resource name.
   *
   * <p>Valid values have the format: projects/ * /locations/ * /keyRings/ * /cryptoKeys/ *
   * /cryptoKeyVersions/ *. See https://cloud.google.com/kms/docs/object-hierarchy.
   */
  public static void validateKeyName(String keyName) throws GeneralSecurityException {
    if (keyName == null) {
      throw new GeneralSecurityException("The keyName is null.");
    }
    if (!KEY_NAME_MATCHER.matcher(keyName).matches()) {
      throw new GeneralSecurityException("The keyName must follow " + KEY_NAME_PATTERN);
    }
  }

  /**
   * Verifies that the CRC32C checksum returned by KMS matches the public key, to detect corruption
   * of the {@code GetPublicKey} response in transit.
   */
  public static void verifyPublicKeyChecksum(PublicKey publicKey) throws GeneralSecurityException {
    if (!publicKey.hasPemCrc32C()) {
      throw new GeneralSecurityException("KMS GetPublicKey response did not include a checksum.");
    }
    long computedCrc32c =
        Hashing.crc32c().hashBytes(publicKey.getPemBytes().asReadOnlyByteBuffer()).padToLong();
    if (computedCrc32c != publicKey.getPemCrc32C().getValue()) {
      throw new GeneralSecurityException(
          "The GetPublicKey checksum does not match the public key.");
    }
  }

  private GcpKmsUtil() {}
}
