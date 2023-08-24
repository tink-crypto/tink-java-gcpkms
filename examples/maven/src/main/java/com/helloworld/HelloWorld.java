/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

package com.helloworld;

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.KmsClient;
import com.google.crypto.tink.TinkJsonProtoKeysetFormat;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.PredefinedAeadParameters;
import com.google.crypto.tink.integration.gcpkms.GcpKmsClient;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * Encrypts a string
 *
 * <p>This application uses the <a href="https://github.com/tink-crypto/tink-java">Tink<a/> crypto
 * library with the <a href="https://github.com/tink-crypto/tink-java-gcpkms">Google Cloud KMS
 * extension<a/>.
 */
public final class HelloWorld {

  private static final byte[] plaintext = "HelloWorld".getBytes();
  private static final byte[] associatedData = "Associated Data".getBytes();

  private static void usage() {
    System.out.println(
        "Usage: mvn exec:java "
            + "-Dexec.args=\"<keyset file> <credentials path> <keyset encryption key uri>\"");
  }

  /** Loads a KeysetHandle from {@code keyset} or generate a new one if it doesn't exist. */
  private static KeysetHandle getKeysetHandle(Path keysetPath, Aead keysetEncryptionAead)
      throws GeneralSecurityException, IOException {
    if (Files.exists(keysetPath)) {
      return TinkJsonProtoKeysetFormat.parseEncryptedKeyset(
          new String(Files.readAllBytes(keysetPath), UTF_8), keysetEncryptionAead, new byte[0]);
    }
    KeysetHandle handle = KeysetHandle.generateNew(PredefinedAeadParameters.AES128_GCM);
    String serializedEncryptedKeyset =
        TinkJsonProtoKeysetFormat.serializeEncryptedKeyset(
            handle, keysetEncryptionAead, new byte[0]);
    Files.write(keysetPath, serializedEncryptedKeyset.getBytes(UTF_8));
    return handle;
  }

  private static byte[] encrypt(Path keyset, Aead keysetEncryptionAead, byte[] plaintext)
      throws Exception {
    KeysetHandle keysetHandle = getKeysetHandle(keyset, keysetEncryptionAead);
    Aead aead = keysetHandle.getPrimitive(Aead.class);
    return aead.encrypt(plaintext, associatedData);
  }

  private static byte[] decrypt(Path keyset, Aead keysetEncryptionAead, byte[] ciphertext)
      throws Exception {
    KeysetHandle keysetHandle = getKeysetHandle(keyset, keysetEncryptionAead);
    Aead aead = keysetHandle.getPrimitive(Aead.class);
    return aead.decrypt(ciphertext, associatedData);
  }

  public static void main(String[] args) throws Exception {
    if (args.length < 3) {
      usage();
      System.exit(1);
    }

    Path keysetFile = Paths.get(args[0]);
    Path credentialsPath = Paths.get(args[1]);
    String keysetEncryptionKeyUri = args[2];

    // Register all AEAD key types with the Tink runtime.
    AeadConfig.register();
    KmsClient kmsClient = new GcpKmsClient().withCredentials(credentialsPath.toString());
    Aead keysetEncryptionAead = kmsClient.getAead(keysetEncryptionKeyUri);

    byte[] ciphertext = encrypt(keysetFile, keysetEncryptionAead, plaintext);
    byte[] decrypted = decrypt(keysetFile, keysetEncryptionAead, ciphertext);

    if (!Arrays.equals(decrypted, plaintext)) {
      System.out.println("Decryption failed");
      System.exit(1);
    }
  }

  private HelloWorld() {}
}
