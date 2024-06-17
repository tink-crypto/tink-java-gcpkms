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

# Builds and tests tink-java-gcpkms and its examples using Maven.
#
# The behavior of this script can be modified using the following optional env
# variables:
#
# - CONTAINER_IMAGE (unset by default): By default when run locally this script
#   executes tests directly on the host. The CONTAINER_IMAGE variable can be set
#   to execute tests in a custom container image for local testing. E.g.:
#
#   CONTAINER_IMAGE="us-docker.pkg.dev/tink-test-infrastructure/tink-ci-images/linux-tink-java-base:latest" \
#     sh ./kokoro/gcp_ubuntu/maven/run_tests.sh
set -eEuo pipefail

readonly GITHUB_ORG="https://github.com/tink-crypto"

IS_KOKORO="false"
if [[ -n "${KOKORO_ARTIFACTS_DIR:-}" ]] ; then
  IS_KOKORO="true"
fi
readonly IS_KOKORO

RUN_COMMAND_ARGS=()
if [[ "${IS_KOKORO}" == "true" ]] ; then
  readonly TINK_BASE_DIR="$(echo "${KOKORO_ARTIFACTS_DIR}"/git*)"
  cd "${TINK_BASE_DIR}/tink_java_gcpkms"
  source ./kokoro/testutils/java_test_container_images.sh
  CONTAINER_IMAGE="${TINK_JAVA_BASE_IMAGE}"
  RUN_COMMAND_ARGS+=( -k "${TINK_GCR_SERVICE_KEY}" )
fi
readonly CONTAINER_IMAGE

if [[ -n "${CONTAINER_IMAGE:-}" ]]; then
  RUN_COMMAND_ARGS+=( -c "${CONTAINER_IMAGE}" )
fi

# File that stores environment variables to pass to the container.
readonly ENV_VARIABLES_FILE="/tmp/env_variables.txt"

if [[ -n "${TINK_REMOTE_BAZEL_CACHE_GCS_BUCKET:-}" ]]; then
  cp "${TINK_REMOTE_BAZEL_CACHE_SERVICE_KEY}" ./cache_key
  cat <<EOF > "${ENV_VARIABLES_FILE}"
BAZEL_REMOTE_CACHE_NAME=${TINK_REMOTE_BAZEL_CACHE_GCS_BUCKET}/bazel/${TINK_JAVA_BASE_IMAGE_HASH}
EOF
  RUN_COMMAND_ARGS+=( -e "${ENV_VARIABLES_FILE}" )
fi

cat <<'EOF' > _do_run_test.sh
set -euo pipefail

readonly MAVEN_POM_FILE="maven/tink-java-gcpkms.pom.xml"
# Ignore com.google.crypto.tink:tink; this is a Bazel dependency, not a Maven
# one.
./kokoro/testutils/check_maven_bazel_deps_consistency.sh \
  -e "com.google.crypto.tink:tink" "//:tink-gcpkms" "${MAVEN_POM_FILE}"

MAVEN_DEPLOY_LIBRARY_OPTS=()
if [[ -n "${BAZEL_REMOTE_CACHE_NAME:-}" ]]; then
  MAVEN_DEPLOY_LIBRARY_OPTS+=( -c "${BAZEL_REMOTE_CACHE_NAME}" )
fi
readonly MAVEN_DEPLOY_LIBRARY_OPTS

./maven/maven_deploy_library.sh "${MAVEN_DEPLOY_LIBRARY_OPTS[@]}" install \
  tink-gcpkms "${MAVEN_POM_FILE}" HEAD

readonly CREDENTIALS_FILE_PATH="testdata/gcp/credential.json"
readonly KMS_KEY_URI="gcp-kms://projects/tink-test-infrastructure/locations/global/keyRings/unit-and-integration-testing/cryptoKeys/aead-key"

# Run the local test Maven example.
mvn package --no-snapshot-updates -f examples/maven/pom.xml
mvn exec:java --no-snapshot-updates -f examples/maven/pom.xml \
  -Dexec.args="keyset.json ${CREDENTIALS_FILE_PATH} ${KMS_KEY_URI}"
EOF

chmod +x _do_run_test.sh

./kokoro/testutils/copy_credentials.sh "testdata" "gcp"

# Run cleanup on EXIT.
trap cleanup EXIT

cleanup() {
  rm -rf _do_run_test.sh "${ENV_VARIABLES_FILE}"
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
  cat <<EOF >> "${ENV_VARIABLES_FILE}"
SONATYPE_USERNAME
SONATYPE_PASSWORD
EOF
  RUN_COMMAND_ARGS+=( -e "${ENV_VARIABLES_FILE}" )

  ./kokoro/testutils/run_command.sh "${RUN_COMMAND_ARGS[@]}" \
    ./maven/maven_deploy_library.sh -u "${GITHUB_URL}" snapshot tink-gcpkms \
    maven/tink-java-gcpkms.pom.xml HEAD
fi
