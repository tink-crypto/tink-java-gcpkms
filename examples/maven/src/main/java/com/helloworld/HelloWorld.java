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

  /** Creates a new keyset with one AEAD key, and write it encrypted to disk. */
  private static void createAndWriteEncryptedKeyset(Path keysetPath, Aead keysetEncryptionAead)
      throws GeneralSecurityException, IOException {
    KeysetHandle handle = KeysetHandle.generateNew(PredefinedAeadParameters.AES128_GCM);
    String serializedEncryptedKeyset =
        TinkJsonProtoKeysetFormat.serializeEncryptedKeyset(
            handle, keysetEncryptionAead, new byte[0]);
    Files.write(keysetPath, serializedEncryptedKeyset.getBytes(UTF_8));
  }

  /** Reads an encrypted keyset from disk. */
  private static KeysetHandle readEncryptedKeyset(Path keysetPath, Aead keysetEncryptionAead)
      throws GeneralSecurityException, IOException {
    return TinkJsonProtoKeysetFormat.parseEncryptedKeyset(
        new String(Files.readAllBytes(keysetPath), UTF_8), keysetEncryptionAead, new byte[0]);
  }

  public static void main(String[] args) throws Exception {
    if (args.length < 3) {
      usage();
      System.exit(1);
    }

    Path keysetPath = Paths.get(args[0]);
    Path credentialsPath = Paths.get(args[1]);
    String keysetEncryptionKeyUri = args[2];

    // Register all AEAD key types with the Tink runtime.
    AeadConfig.register();
    KmsClient kmsClient = new GcpKmsClient().withCredentials(credentialsPath.toString());
    Aead keysetEncryptionAead = kmsClient.getAead(keysetEncryptionKeyUri);

    if (Files.exists(keysetPath)) {
      System.out.println("keyset file already exists");
      System.exit(1);
    }

    createAndWriteEncryptedKeyset(keysetPath, keysetEncryptionAead);

    KeysetHandle keysetHandle = readEncryptedKeyset(keysetPath, keysetEncryptionAead);
    Aead aead = keysetHandle.getPrimitive(Aead.class);

    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    byte[] decrypted = aead.decrypt(ciphertext, associatedData);
    if (!Arrays.equals(decrypted, plaintext)) {
      System.out.println("Decryption failed");
      System.exit(1);
    }
  }

  private HelloWorld() {}
}
