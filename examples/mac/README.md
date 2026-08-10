# Java MAC example

This example shows how to compute and verify message authentication codes (MACs)
with Tink using a
[Cloud KMS MAC key](https://cloud.google.com/kms/docs/create-validate-mac).

Cloud KMS acts as a crypto oracle for each operation: both computing and
verifying a MAC send the message to Cloud KMS, and the key never leaves Cloud
KMS. Messages are limited to 64 KiB.

The CLI takes the following arguments:

*   `mode`: `compute` or `verify` to indicate if you want to compute a MAC over
    the input or verify one.
*   `key-name`: Resource name of the Cloud KMS CryptoKeyVersion to use, in the
    format
    `projects/<my-project>/locations/global/keyRings/<my-key-ring>/cryptoKeys/<my-key>/cryptoKeyVersions/<my-version>`.
*   `gcp-credential-file`: Name of the file with the GCP credentials in JSON
    format.
*   `input-file`: Read the message to authenticate or verify from this file.
*   `mac-file`: Written by `compute`, read by `verify`.

## Build and Run

### Prerequisite

This example uses a Cloud KMS MAC key. In order to run it, you need to:

*   Create a MAC key on Cloud KMS. Copy the resource name of the key version you
    want to use.

*   Create and download a service account that is allowed to compute and verify
    MACs with the above key.

### Bazel

```shell
git clone https://github.com/tink-crypto/tink-java-gcpkms
cd examples
bazel build ...
```

You can then compute a MAC over a file:

```shell
echo "some data" > testdata.txt
# Replace `<my-key-version-name>` with the resource name of your CryptoKeyVersion,
# and my-service-account.json with your service account's credential JSON file.
./bazel-bin/mac/mac_example compute \
    <my-key-version-name> \
    my-service-account.json \
    testdata.txt testdata-mac.bin
```

or verify the MAC with:

```shell
./bazel-bin/mac/mac_example verify \
    <my-key-version-name> \
    my-service-account.json \
    testdata.txt testdata-mac.bin
```
