# Hello World for Tink Java Cloud KMS

This is a simple example showing how to use the Tink Java Google Cloud KMS
integration with Maven. To build and run this example:

```shell
git clone https://github.com/tink-crypto/tink-java-awskms
cd tink-java-awskms
# Use your credentials and key URI here.
readonly CREDENTIALS_FILE_PATH="testdata/gcp/credential.json"
readonly MASTER_KEY_URI="gcp-kms://projects/tink-test/locations/global/
keyRings/unit-test/cryptoKeys/aead-key"
mvn package -f examples/maven/pom.xml
mvn exec:java -f examples/maven/pom.xml \
  -Dexec.args="keyset.json ${CREDENTIALS_FILE_PATH} ${MASTER_KEY_URI}" \
  && echo "OK!"
```
