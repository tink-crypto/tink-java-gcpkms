# Java envelope encryption example

This example shows how to encrypt data with Tink using
[Envelope Encryption](https://cloud.google.com/kms/docs/envelope-encryption).

It shows how you can use Tink to encrypt data with a newly generated *data
encryption key* (DEK) which is wrapped with a KMS key. The data will be
encrypted with AES256 GCM using the DEK and the DEK will be encrypted with the
KMS key and stored alongside the ciphertext.

The CLI takes the following arguments:

*   mode: "encrypt" or "decrypt" to indicate if you want to encrypt or decrypt.
*   kek-uri: The URI for the key to be used for envelope encryption.
*   gcp-credential-file: Name of the file with the GCP credentials in JSON
    format.
*   input-file: Read the input from this file.
*   output-file: Write the result to this file.
*   [optional] associated-data: Associated data used for the encryption or
    decryption.

## Build and Run

### Prequisite

This envelope encryption example uses a Cloud KMS key as a key-encryption key
(KEK). In order to run it, you need to:

*   Create a symmetric key on Cloud KMs. Copy the key URI which is in this
    format:
    `projects/<my-project>/locations/global/keyRings/<my-key-ring>/cryptoKeys/<my-key>`.

*   Create and download a service account that is allowed to encrypt and decrypt
    with the above key.

### Bazel

```shell
git clone https://github.com/google/tink
cd tink/examples/java_src
bazel build ...
```

You can then encrypt a file:

```shell
echo "some data" > testdata.txt
# Replace `<my-key-uri>` in `gcp-kms://<my-key-uri>` with your key URI, and
# my-service-account.json with your service account's credential JSON file.
./bazel-bin/envelopeaead/envelope_aead_example encrypt \
    my-service-account.json \
    gcp-kms://<my-key-uri> \
    testdata.txt testdata.txt.encrypted
```

or decrypt the file with:

```shell
./bazel-bin/envelopeaead/envelope_aead_example decrypt \
    my-service-account.json \
    gcp-kms://<my-key-uri> \
    testdata.txt.encrypted testdata.txt
```
