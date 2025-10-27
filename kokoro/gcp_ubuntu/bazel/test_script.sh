#!/bin/bash
# Copyright 2024 Google LLC
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

usage() {
  cat <<EOF
Usage:  $0 [-m] [-c Bazel cache name]
  -m: [Optional] If set, run also "manual" Bazel tests that require a GCP
      project.
  -c: [Optional] Bazel cache to use; creadentials are expected to be in a
      cache_key file.
  -h: Help. Print this usage information.
EOF
  exit 1
}

RUN_MANUAL_TESTS="false"
BAZEL_CACHE_NAME=

process_args() {
  # Parse options.
  while getopts "mc:" opt; do
    case "${opt}" in
      m) RUN_MANUAL_TESTS="true" ;;
      c) BAZEL_CACHE_NAME="${OPTARG}" ;;
      *) usage ;;
    esac
  done
  shift $((OPTIND - 1))
  readonly RUN_MANUAL_TESTS
  readonly BAZEL_CACHE_NAME
}

process_args "$@"

trap cleanup EXIT

cleanup() {
  rm -rf BUILD.bazel.temp
}

# Check if the BUILD.bazel file is up-to-date.
./tools/create_maven_build_file.sh -o BUILD.bazel.temp
if ! cmp -s BUILD.bazel BUILD.bazel.temp; then
  cat << EOF >&2
ERROR: Update your BUILD.bazel file using ./tools/create_maven_build_file.sh or
applying:
patch BUILD.bazel<<PATCH
$(diff BUILD.bazel BUILD.bazel.temp)
PATCH
EOF
  exit 1
fi

CACHE_FLAGS=()
if [[ -n "${BAZEL_CACHE_NAME:-}" ]]; then
  CACHE_FLAGS+=( -c "${BAZEL_CACHE_NAME}" )
fi
readonly CACHE_FLAGS

# Build and run unit tests.
ADDITIONAL_MANUAL_TARGETS=()
if [[ "${RUN_MANUAL_TESTS}" == "true" ]]; then
  ADDITIONAL_MANUAL_TARGETS+=(
    "//src/test/java/com/google/crypto/tink/integration/gcpkms:GcpKmsIntegrationTest"
  )
fi
readonly ADDITIONAL_MANUAL_TARGETS

echo "------------------------------------------------------------------------"
echo "Build and run unit tests only relying on WORKSPACE"
echo "------------------------------------------------------------------------"
./kokoro/testutils/run_bazel_tests.sh "${CACHE_FLAGS[@]}" . \
  "${ADDITIONAL_MANUAL_TARGETS[@]}"

echo "------------------------------------------------------------------------"
echo "Build and run unit tests only relying on bzlmod"
echo "------------------------------------------------------------------------"
./kokoro/testutils/run_bazel_tests.sh -b "--enable_bzlmod" \
  -t "--enable_bzlmod" "${CACHE_FLAGS[@]}" . "${ADDITIONAL_MANUAL_TARGETS[@]}"

# Build and run examples.
ADDITIONAL_EXAMPLES_MANUAL_TARGETS=()
if [[ "${RUN_MANUAL_TESTS}" == "true" ]]; then
  ADDITIONAL_EXAMPLES_MANUAL_TARGETS=(
    "//gcs:gcs_envelope_aead_example_test"
    "//encryptedkeyset:encrypted_keyset_example_test"
    "//envelopeaead:envelope_aead_example_test"
  )
fi
readonly ADDITIONAL_EXAMPLES_MANUAL_TARGETS

echo "------------------------------------------------------------------------"
echo "Build and run examples only relying on WORKSPACE"
echo "------------------------------------------------------------------------"
./kokoro/testutils/run_bazel_tests.sh "${CACHE_FLAGS[@]}" "examples" \
  "${ADDITIONAL_EXAMPLES_MANUAL_TARGETS[@]}"

echo "------------------------------------------------------------------------"
echo "Build and run examples only relying on bzlmod"
echo "------------------------------------------------------------------------"
./kokoro/testutils/run_bazel_tests.sh -b "--enable_bzlmod" \
  -t "--enable_bzlmod" "${CACHE_FLAGS[@]}" "examples" \
  "${ADDITIONAL_EXAMPLES_MANUAL_TARGETS[@]}"
