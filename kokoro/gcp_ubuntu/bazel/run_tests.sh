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

RUN_COMMAND_ARGS=()
if [[ -n "${KOKORO_ARTIFACTS_DIR:-}" ]] ; then
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

# Check for dependencies in TINK_BASE_DIR. Any that aren't present will be
# downloaded.
./kokoro/testutils/fetch_git_repo_if_not_present.sh "${TINK_BASE_DIR}" \
  "${GITHUB_ORG}/tink-java"

./kokoro/testutils/copy_credentials.sh "testdata" "gcp"
./kokoro/testutils/copy_credentials.sh "examples/testdata" "gcp"

cp WORKSPACE WORKSPACE.bak
./kokoro/testutils/replace_http_archive_with_local_repository.py \
  -f WORKSPACE -t ..

cat <<'EOF' > _do_run_test.sh
set -euo pipefail

./tools/create_maven_build_file.sh -o BUILD.bazel.temp
if ! cmp -s BUILD.bazel BUILD.bazel.temp; then
  echo -n "ERROR: Update your BUILD.bazel file using" >&2
  echo " ./tools/create_maven_build_file.sh or applying:"
  echo "patch BUILD.bazel<<PATCH"
  echo "$(diff BUILD.bazel BUILD.bazel.temp)"
  echo "PATCH"
EOP
  exit 1
fi
MANUAL_TARGETS=()
if [[ -n "${KOKORO_ROOT:-}" ]]; then
  MANUAL_TARGETS+=(
    "//src/test/java/com/google/crypto/tink/integration/gcpkms:GcpKmsIntegrationTest"
  )
fi
readonly MANUAL_TARGETS
./kokoro/testutils/run_bazel_tests.sh . "${MANUAL_TARGETS[@]}"

# Targets tagged as "manual" that require setting GCP credentials.
EXAMPLES_MANUAL_TARGETS=()
if [[ -n "${KOKORO_ROOT:-}" ]]; then
  EXAMPLES_MANUAL_TARGETS=(
    "//gcs:gcs_envelope_aead_example_test"
    "//encryptedkeyset:encrypted_keyset_example_test"
    "//envelopeaead:envelope_aead_example_test"
  )
fi
readonly EXAMPLES_MANUAL_TARGETS
./kokoro/testutils/run_bazel_tests.sh "examples" "${EXAMPLES_MANUAL_TARGETS[@]}"
EOF
chmod +x _do_run_test.sh

# Run cleanup on EXIT.
trap cleanup EXIT

cleanup() {
  rm -rf _do_run_test.sh
  rm -rf BUILD.bazel.temp
  mv WORKSPACE.bak WORKSPACE
}

# Share the required Kokoro env variables.
cat <<EOF > env_variables.txt
KOKORO_ROOT
EOF
RUN_COMMAND_ARGS+=( -e env_variables.txt )
readonly RUN_COMMAND_ARGS

./kokoro/testutils/run_command.sh "${RUN_COMMAND_ARGS[@]}" ./_do_run_test.sh
