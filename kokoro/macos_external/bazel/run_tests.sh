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

set -euo pipefail

if [[ -n "${KOKORO_ROOT:-}" ]] ; then
  readonly TINK_BASE_DIR="$(echo "${KOKORO_ARTIFACTS_DIR}"/git*)"
  cd "${TINK_BASE_DIR}/tink_java_gcpkms"
  export JAVA_HOME=$(/usr/libexec/java_home -v1.8)
  export XCODE_VERSION="14.1"
  export DEVELOPER_DIR="/Applications/Xcode.app/Contents/Developer"
fi

./kokoro/testutils/copy_credentials.sh "testdata" "gcp"
./kokoro/testutils/copy_credentials.sh "examples/testdata" "gcp"
source ./kokoro/testutils/update_android_sdk.sh

# Run manual tests which rely on key material injected into the Kokoro
# environement.
TINK_JAVA_GCPKMS_RUN_BAZEL_TESTS_ARGS=()

if [[ -n "${TINK_REMOTE_BAZEL_CACHE_GCS_BUCKET:-}" ]]; then
  cp "${TINK_REMOTE_BAZEL_CACHE_SERVICE_KEY}" ./cache_key
  TINK_JAVA_GCPKMS_RUN_BAZEL_TESTS_ARGS+=(
    -c "${TINK_REMOTE_BAZEL_CACHE_GCS_BUCKET}/bazel/macos_tink_java_gcpkms"
  )
fi
TINK_JAVA_GCPKMS_RUN_BAZEL_TESTS_ARGS+=( . )
if [[ -n "${KOKORO_ROOT:-}" ]]; then
  TINK_JAVA_GCPKMS_RUN_BAZEL_TESTS_ARGS+=(
    "//src/test/java/com/google/crypto/tink/integration/gcpkms:GcpKmsIntegrationTest"
  )
fi
readonly TINK_JAVA_GCPKMS_RUN_BAZEL_TESTS_ARGS

./kokoro/testutils/run_bazel_tests.sh \
  "${TINK_JAVA_GCPKMS_RUN_BAZEL_TESTS_ARGS[@]}"

TINK_JAVA_GCPKMS_EXAMPLES_RUN_BAZEL_TESTS_ARGS=()
if [[ -n "${TINK_REMOTE_BAZEL_CACHE_GCS_BUCKET:-}" ]]; then
  TINK_JAVA_GCPKMS_EXAMPLES_RUN_BAZEL_TESTS_ARGS+=(
    -c "${TINK_REMOTE_BAZEL_CACHE_GCS_BUCKET}/bazel/macos_tink_java_gcpkms"
  )
fi
TINK_JAVA_GCPKMS_EXAMPLES_RUN_BAZEL_TESTS_ARGS+=( "examples" )
# Targets tagged as "manual" that require setting GCP credentials.
if [[ -n "${KOKORO_ROOT:-}" ]]; then
  TINK_JAVA_GCPKMS_EXAMPLES_RUN_BAZEL_TESTS_ARGS+=(
    "//gcs:gcs_envelope_aead_example_test"
    "//encryptedkeyset:encrypted_keyset_example_test"
    "//envelopeaead:envelope_aead_example_test"
  )
fi
readonly TINK_JAVA_GCPKMS_EXAMPLES_RUN_BAZEL_TESTS_ARGS

./kokoro/testutils/run_bazel_tests.sh \
  "${TINK_JAVA_GCPKMS_EXAMPLES_RUN_BAZEL_TESTS_ARGS[@]}"
