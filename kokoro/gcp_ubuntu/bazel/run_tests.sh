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
# Prints and error message with the missing deps for the given target diff-ing
# the expected and actual list of targets.
#
# Globals:
#   None
# Arguments:
#   target: Bazel target.
#   expected_deps: Expected list of dependencies.
#   actual_deps: Actual list of dependencies.
# Outputs:
#   Writes to stdout
#######################################
print_missing_deps() {
  local -r target="$1"
  local -r expected_deps="$2"
  local -r actual_deps="$3"

  echo "#========= ERROR ${target} target:"
  echo "The following dependencies are missing from the ${target} target:"
  diff --changed-group-format='%>' --unchanged-group-format='' \
    "${actual_deps}" "${expected_deps}"
  echo "#==============================="
}

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
  local -r tink_java_prefix="//src/main/java/com/google/crypto/tink"
  local -r tink_java_integration_gcpkms_prefix="${tink_java_prefix}/integration/gcpkms"

  # Targets in tink_java_integration_gcpkms_prefix of type java_library,
  # excluding testonly targets.
  local -r expected_gcpkms_deps="$(mktemp)"
  "${BAZEL_CMD}" query "\
kind(java_library,${tink_java_integration_gcpkms_prefix}/...) \
except attr(testonly,1,${tink_java_integration_gcpkms_prefix}/...)" \
    > "${expected_gcpkms_deps}"

  # Dependencies of //:tink-gcpkms of type java_library that are in
  # tink_java_integration_gcpkms_prefix.
  # Note: Considering only direct dependencies of the target.
  local -r actual_gcpkms_targets="$(mktemp)"
  "${BAZEL_CMD}" query "filter(\
${tink_java_integration_gcpkms_prefix},\
kind(java_library,deps(//:tink-gcpkms,1)))" \
    > "${actual_gcpkms_targets}"

  if ! cmp -s "${actual_gcpkms_targets}" "${expected_gcpkms_deps}"; then
    print_missing_deps "//:tink-gcpkms" "${expected_gcpkms_deps}" \
      "${actual_gcpkms_targets}"
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
