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
  TINK_BASE_DIR="$(echo "${KOKORO_ARTIFACTS_DIR}"/git*)"
  cd "${TINK_BASE_DIR}/tink_java_gcpkms"
  use_bazel.sh "$(cat .bazelversion)"
fi

: "${TINK_BASE_DIR:=$(cd .. && pwd)}"

# Check for dependencies in TINK_BASE_DIR. Any that aren't present will be
# downloaded.
readonly GITHUB_ORG="https://github.com/tink-crypto"
./kokoro/testutils/fetch_git_repo_if_not_present.sh "${TINK_BASE_DIR}" \
  "${GITHUB_ORG}/tink-java"

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
    "//src/test/java/com/google/crypto/tink/integration/gcpkms:GcpKmsIntegrationTest"
  )
fi
readonly MANUAL_TARGETS

./kokoro/testutils/run_bazel_tests.sh . "${MANUAL_TARGETS[@]}"
