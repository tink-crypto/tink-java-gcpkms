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

# If we are running on Kokoro cd into the repository.
if [[ -n "${KOKORO_ROOT:-}" ]]; then
  cd "${KOKORO_ARTIFACTS_DIR}/git/tink_java"
  use_bazel.sh "$(cat examples/.bazelversion)"
fi

TINK_BASE_DIR="$(pwd)/.."

# Note: When running on the Kokoro CI, we expect these two folders to exist:
#
#  ${KOKORO_ARTIFACTS_DIR}/git/tink_java
#  ${KOKORO_ARTIFACTS_DIR}/git/tink_java_gcpkms
#
# If running locally make sure ../tink_java exists.
if [[ ! -d "${TINK_BASE_DIR}/tink_java" ]]; then
  git clone "https://github.com/tink-crypto/tink-java.git" \
    "${TINK_BASE_DIR}/tink_java"
fi

# Sourcing required to update caller's environment.
source ./kokoro/testutils/install_python3.sh
./kokoro/testutils/copy_credentials.sh "examples/testdata"
./kokoro/testutils/update_android_sdk.sh

cp "examples/WORKSPACE" "examples/WORKSPACE.bak"

./kokoro/testutils/replace_http_archive_with_local_repository.py \
  -f "examples/WORKSPACE" \
  -t "${TINK_BASE_DIR}"

# Targets tagged as "manual" that require setting GCP credentials.
MANUAL_EXAMPLE_JAVA_TARGETS=()
if [[ -n "${KOKORO_ROOT:-}" ]]; then
  MANUAL_EXAMPLE_JAVA_TARGETS=(
    "//gcs:gcs_envelope_aead_example_test"
    "//encryptedkeyset:encrypted_keyset_example_test"
    "//envelopeaead:envelope_aead_example_test"
  )
fi
readonly MANUAL_EXAMPLE_JAVA_TARGETS

./kokoro/testutils/run_bazel_tests.sh \
  "examples" \
  "${MANUAL_EXAMPLE_JAVA_TARGETS[@]}"

mv "examples/WORKSPACE.bak" "examples/WORKSPACE"
