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

export XCODE_VERSION=11.3
export DEVELOPER_DIR="/Applications/Xcode_${XCODE_VERSION}.app/Contents/Developer"
export ANDROID_HOME="/Users/kbuilder/Library/Android/sdk"
export COURSIER_OPTS="-Djava.net.preferIPv6Addresses=true"

if [[ -n "${KOKORO_ROOT:-}" ]] ; then
  cd "${KOKORO_ARTIFACTS_DIR}/git/tink_java_gcpkms"
  use_bazel.sh "$(cat .bazelversion)"
fi

readonly TINK_BASE_DIR="$(pwd)/.."

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

./kokoro/testutils/copy_credentials.sh "testdata" "gcp"
./kokoro/testutils/update_android_sdk.sh
./kokoro/testutils/replace_http_archive_with_local_repository.py \
  -f "WORKSPACE" \
  -t "${TINK_BASE_DIR}"

# Run manual tests which rely on key material injected into the Kokoro
# environement.
MANUAL_TARGETS=()
if [[ -n "${KOKORO_ROOT:-}" ]]; then
  MANUAL_TARGETS+=(
    "//src/test/java/com/google/crypto/tink/integration/gcpkms:KmsAeadKeyManagerWithGcpTest"
    "//src/test/java/com/google/crypto/tink/integration/gcpkms:KmsEnvelopeAeadKeyManagerWithGcpTest"
  )
fi
readonly MANUAL_TARGETS

./kokoro/testutils/run_bazel_tests.sh . "${MANUAL_TARGETS[@]}"
