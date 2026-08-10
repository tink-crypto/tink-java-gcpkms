# Java digital signatures example

This example shows how to sign and verify data with Tink using a
[Cloud KMS asymmetric signing key](https://cloud.google.com/kms/docs/create-validate-signatures).

`Sign` sends the message (or, for some algorithms, only its digest) to Cloud
KMS; the private key never leaves Cloud KMS. `Verify` fetches the public key
from Cloud KMS once and then verifies the signature locally, without further
Cloud KMS calls. `Verify-offline` verifies the signature using a pre-fetched
public key without contacting Cloud KMS.

The CLI takes the following arguments:

*   `mode`: `sign`, `verify`, or `verify-offline` to indicate if you want to
    sign the input, verify a signature over it with Cloud KMS, or verify a
    signature offline using a pre-fetched public key.
*   `key-name`: Resource name of the Cloud KMS CryptoKeyVersion to use, in the
    format
    `projects/<my-project>/locations/global/keyRings/<my-key-ring>/cryptoKeys/<my-key>/cryptoKeyVersions/<my-version>`.
    Can be empty (`""`) when `mode` is `verify-offline`.
*   `gcp-credential-file`: Name of the file with the GCP credentials in JSON
    format. Can be empty (`""`) when `mode` is `verify-offline`.
*   `input-file`: Read the message to sign or verify from this file.
*   `signature-file`: Written by "sign", read by "verify" and "verify-offline".
*   `public-key-file`: Optional argument required for `verify-offline`; file
    containing the pre-fetched public key bytes.
*   `algorithm`: Optional argument required for `verify-offline`; the Cloud KMS
    CryptoKeyVersionAlgorithm (e.g., `EC_SIGN_P256_SHA256`).

This example is set up for the classical signature algorithms (ECDSA and RSA).
Post-quantum keys need extra runtime dependencies that the example does not
declare: verifying ML-DSA or SLH-DSA signatures requires a Conscrypt provider
supporting those algorithms to be installed, and signing with an external-mu
ML-DSA key requires `org.bouncycastle:bcprov-jdk18on` on the runtime classpath.

## Build and Run

### Prerequisite

This example uses a Cloud KMS asymmetric signing key. In order to run it, you
need to:

*   Create an asymmetric signing key on Cloud KMS. Copy the resource name of the
    key version you want to use.

*   Create and download a service account that is allowed to sign with the above
    key and to get its public key.

### Bazel

```shell
git clone https://github.com/tink-crypto/tink-java-gcpkms
cd examples
bazel build ...
```

You can then sign a file:

```shell
echo "some data" > testdata.txt
# Replace `<my-key-version-name>` with the resource name of your CryptoKeyVersion,
# and my-service-account.json with your service account's credential JSON file.
./bazel-bin/signature/signature_example sign \
    <my-key-version-name> \
    my-service-account.json \
    testdata.txt testdata.sig
```

or verify the signature with:

```shell
./bazel-bin/signature/signature_example verify \
    <my-key-version-name> \
    my-service-account.json \
    testdata.txt testdata.sig
```

or verify the signature offline using a pre-fetched public key with:

```shell
# For verify-offline, key-name and gcp-credential-file can be empty strings ("").
./bazel-bin/signature/signature_example verify-offline \
    "" \
    "" \
    testdata.txt testdata.sig \
    public_key.pem \
    EC_SIGN_P256_SHA256
```
