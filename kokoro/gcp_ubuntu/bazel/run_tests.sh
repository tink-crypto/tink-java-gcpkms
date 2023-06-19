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

readonly GITHUB_ORG="https://github.com/tink-crypto"
TINK_BASE_DIR=
BAZEL_CMD="bazel"

#######################################
# Checks if the //:tink-gcpkms has all the required dependencies.
#
# Globals:
#   None
# Arguments:
#   None
# Outputs:
#   Writes to stdout
#######################################
test_build_bazel_file() {
  ./tools/create_maven_build_file.sh -o BUILD.bazel.temp
  if ! cmp -s BUILD.bazel BUILD.bazel.temp; then
    echo "ERROR: Update your BUILD.bazel file using \
./tools/create_maven_build_file.sh or applying:" >&2
    cat <<EOF
patch BUILD.bazel<<PATCH
$(diff BUILD.bazel BUILD.bazel.temp)
PATCH
EOF
    exit 1
  fi
}

main() {
  if [[ -n "${KOKORO_ARTIFACTS_DIR:-}" ]] ; then
    TINK_BASE_DIR="$(echo "${KOKORO_ARTIFACTS_DIR}"/git*)"
    cd "${TINK_BASE_DIR}/tink_java_gcpkms"
  fi

  : "${TINK_BASE_DIR:=$(cd .. && pwd)}"
  readonly TINK_BASE_DIR

  # Prefer using Bazelisk if available.
  if command -v "bazelisk" &> /dev/null; then
    BAZEL_CMD="bazelisk"
  fi
  readonly BAZEL_CMD

  # Check for dependencies in TINK_BASE_DIR. Any that aren't present will be
  # downloaded.
  ./kokoro/testutils/fetch_git_repo_if_not_present.sh "${TINK_BASE_DIR}" \
    "${GITHUB_ORG}/tink-java"

  ./kokoro/testutils/copy_credentials.sh "testdata" "gcp"
  ./kokoro/testutils/replace_http_archive_with_local_repository.py \
    -f "WORKSPACE" -t "${TINK_BASE_DIR}"

  # Make sure dependencies of //:tink-gcpkms are correct.
  test_build_bazel_file

  # Run manual tests which rely on key material injected into the Kokoro
  # environement.
  MANUAL_TARGETS=()
  if [[ -n "${KOKORO_ARTIFACTS_DIR:-}" ]]; then
    MANUAL_TARGETS+=(
      "//src/test/java/com/google/crypto/tink/integration/gcpkms:GcpKmsIntegrationTest"
    )
  fi
  readonly MANUAL_TARGETS

  ./kokoro/testutils/run_bazel_tests.sh . "${MANUAL_TARGETS[@]}"
}

main "$@"
