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

# Builds and tests tink-java-gcpkms using Bazel.
#
# The behavior of this script can be modified using the following optional env
# variables:
#
# - CONTAINER_IMAGE (unset by default): By default when run locally this script
#   executes tests directly on the host. The CONTAINER_IMAGE variable can be set
#   to execute tests in a custom container image for local testing. E.g.:
#
#   CONTAINER_IMAGE="us-docker.pkg.dev/tink-test-infrastructure/tink-ci-images/linux-tink-java-base:latest" \
#     sh ./kokoro/gcp_ubuntu/bazel/run_tests.sh
set -eEuo pipefail

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

if [[ -n "${TINK_REMOTE_BAZEL_CACHE_GCS_BUCKET:-}" ]]; then
  cp "${TINK_REMOTE_BAZEL_CACHE_SERVICE_KEY}" ./cache_key
  cat <<EOF > /tmp/env_variables.txt
BAZEL_REMOTE_CACHE_NAME=${TINK_REMOTE_BAZEL_CACHE_GCS_BUCKET}/bazel/${TINK_JAVA_BASE_IMAGE_HASH}
EOF
  RUN_COMMAND_ARGS+=( -e /tmp/env_variables.txt )
fi

./kokoro/testutils/copy_credentials.sh "testdata" "gcp"
./kokoro/testutils/copy_credentials.sh "examples/testdata" "gcp"

cat <<'EOF' > _do_run_test.sh
set -euo pipefail

./tools/create_maven_build_file.sh -o BUILD.bazel.temp
if ! cmp -s BUILD.bazel BUILD.bazel.temp; then
  echo -n "ERROR: Update your BUILD.bazel file using" >&2
  echo " ./tools/create_maven_build_file.sh or applying:"
  echo "patch BUILD.bazel<<PATCH"
  echo "$(diff BUILD.bazel BUILD.bazel.temp)"
  echo "PATCH"
  exit 1
fi
MANUAL_TARGETS=()
if [[ -n "${KOKORO_ROOT:-}" ]]; then
  MANUAL_TARGETS+=(
    "//src/test/java/com/google/crypto/tink/integration/gcpkms:GcpKmsIntegrationTest"
  )
fi
readonly MANUAL_TARGETS

CACHE_FLAGS=()
if [[ -n "${BAZEL_REMOTE_CACHE_NAME:-}" ]]; then
  CACHE_FLAGS+=( -c "${BAZEL_REMOTE_CACHE_NAME}" )
fi
readonly CACHE_FLAGS

./kokoro/testutils/run_bazel_tests.sh "${CACHE_FLAGS[@]}" . \
  "${MANUAL_TARGETS[@]}"

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
./kokoro/testutils/run_bazel_tests.sh "${CACHE_FLAGS[@]}" "examples" \
  "${EXAMPLES_MANUAL_TARGETS[@]}"
EOF
chmod +x _do_run_test.sh

# Run cleanup on EXIT.
trap cleanup EXIT

cleanup() {
  rm -rf _do_run_test.sh
  rm -rf BUILD.bazel.temp
}

# Share the required Kokoro env variables.
cat <<EOF > env_variables.txt
KOKORO_ROOT
EOF
RUN_COMMAND_ARGS+=( -e env_variables.txt )
readonly RUN_COMMAND_ARGS

./kokoro/testutils/run_command.sh "${RUN_COMMAND_ARGS[@]}" ./_do_run_test.sh
