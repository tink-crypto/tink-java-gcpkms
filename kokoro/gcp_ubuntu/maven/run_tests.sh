#!/bin/bash
# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
################################################################################

# By default when run locally this script runs the command below directly on the
# host. The CONTAINER_IMAGE variable can be set to run on a custom container
# image for local testing. E.g.:
#
# CONTAINER_IMAGE="us-docker.pkg.dev/tink-test-infrastructure/tink-ci-images/linux-tink-cc-cmake:latest" \
#  sh ./kokoro/gcp_ubuntu/bazel_fips/run_tests.sh
#
# The user may specify TINK_BASE_DIR as the folder where to look for
# tink-java-gcpkms and its depndencies. That is:
#   ${TINK_BASE_DIR}/tink_java
#   ${TINK_BASE_DIR}/tink_java_gcpkms
set -eEuo pipefail

readonly GITHUB_ORG="https://github.com/tink-crypto"

IS_KOKORO="false"
if [[ -n "${KOKORO_ARTIFACTS_DIR:-}" ]] ; then
  IS_KOKORO="true"
fi
readonly IS_KOKORO

RUN_COMMAND_ARGS=()
if [[ "${IS_KOKORO}" == "true" ]] ; then
  TINK_BASE_DIR="$(echo "${KOKORO_ARTIFACTS_DIR}"/git*)"
  source \
    "${TINK_BASE_DIR}/tink_java_gcpkms/kokoro/testutils/tink_test_container_images.sh"
  CONTAINER_IMAGE="${TINK_JAVA_BASE_IMAGE}"
  RUN_COMMAND_ARGS+=( -k "${TINK_GCR_SERVICE_KEY}" )
fi

: "${TINK_BASE_DIR:=$(cd .. && pwd)}"
readonly TINK_BASE_DIR
readonly CONTAINER_IMAGE

cd "${TINK_BASE_DIR}/tink_java_gcpkms"

if [[ -n "${CONTAINER_IMAGE:-}" ]]; then
  RUN_COMMAND_ARGS+=( -c "${CONTAINER_IMAGE}" )
fi

cat <<'EOF' > _do_run_test.sh
set -euo pipefail

readonly MAVEN_POM_FILE="maven/tink-java-gcpkms.pom.xml"
# Ignore com.google.crypto.tink:tink; this is a Bazel dependency, not a Maven one.
./kokoro/testutils/check_maven_bazel_deps_consistency.sh \
  -e "com.google.crypto.tink:tink" "//:tink-gcpkms" "${MAVEN_POM_FILE}"

# Install the latest snapshots locally.
(
  cd ../tink_java
  ./maven/maven_deploy_library.sh install tink \
    maven/tink-java.pom.xml HEAD
)

# Build tink-java-gcpkms against tink-java at HEAD-SNAPSHOT.
mvn versions:set-property -Dproperty=tink.version -DnewVersion=HEAD-SNAPSHOT \
  --file "${MAVEN_POM_FILE}"

./maven/maven_deploy_library.sh install tink-gcpkms "${MAVEN_POM_FILE}" HEAD

readonly CREDENTIALS_FILE_PATH="testdata/gcp/credential.json"
readonly KMS_KEY_URI="gcp-kms://projects/tink-test-infrastructure/locations/global/keyRings/unit-and-integration-testing/cryptoKeys/aead-key"

# Run the local test Maven example.
mvn package --no-snapshot-updates -f examples/maven/pom.xml
mvn exec:java --no-snapshot-updates -f examples/maven/pom.xml \
  -Dexec.args="keyset.json ${CREDENTIALS_FILE_PATH} ${KMS_KEY_URI}"
EOF

chmod +x _do_run_test.sh

# Check for dependencies in TINK_BASE_DIR. Any that aren't present will be
# downloaded.
./kokoro/testutils/fetch_git_repo_if_not_present.sh "${TINK_BASE_DIR}" \
  "${GITHUB_ORG}/tink-java"

cp WORKSPACE WORKSPACE.bak

./kokoro/testutils/replace_http_archive_with_local_repository.py \
  -f WORKSPACE -t ..
./kokoro/testutils/copy_credentials.sh "testdata" "gcp"

# Run cleanup on EXIT.
trap cleanup EXIT

cleanup() {
  rm -rf _do_run_test.sh
  mv WORKSPACE.bak WORKSPACE
}

./kokoro/testutils/run_command.sh "${RUN_COMMAND_ARGS[@]}" ./_do_run_test.sh

readonly GITHUB_JOB_NAME="tink/github/java_gcpkms/gcp_ubuntu/maven/continuous"

if [[ "${IS_KOKORO}" == "true" \
      && "${KOKORO_JOB_NAME}" == "${GITHUB_JOB_NAME}" ]]; then
  # GITHUB_ACCESS_TOKEN is populated by Kokoro.
  readonly GIT_CREDENTIALS="ise-crypto:${GITHUB_ACCESS_TOKEN}"
  readonly GITHUB_URL="https://${GIT_CREDENTIALS}@github.com/tink-crypto/tink-java-gcpkms.git"

  # Share the required env variables with the container to allow publishing the
  # snapshot on Sonatype.
  cat <<EOF > env_variables.txt
SONATYPE_USERNAME
SONATYPE_PASSWORD
EOF
  RUN_COMMAND_ARGS+=( -e env_variables.txt )

  ./kokoro/testutils/run_command.sh "${RUN_COMMAND_ARGS[@]}" \
    ./maven/maven_deploy_library.sh -u "${GITHUB_URL}" snapshot tink-gcpkms \
    maven/tink-java-gcpkms.pom.xml HEAD
fi
