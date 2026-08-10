#!/bin/bash
# Copyright 2026 Google LLC
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

#############################################################################
##### Tests for the Google Cloud KMS digital signature example.

CLI="$1"
KEY_NAME="$2"
CRED_FILE="$3"
PUB_KEY_FILE="$4"

ALGORITHM="EC_SIGN_P256_SHA256"


DATA_FILE="$TEST_TMPDIR/example_data.txt"
SIGNATURE_FILE="$TEST_TMPDIR/example_data.sig"

echo "This is some message to sign." > ${DATA_FILE}

#############################################################################

# A helper function for getting the return code of a command that may fail
# Temporarily disables error safety and stores return value in ${TEST_STATUS}
# Usage:
# % test_command somecommand some args
# % echo ${TEST_STATUS}
test_command() {
  set +e
  "$@"
  TEST_STATUS=$?
  set -e
}

#############################################################################
#### Test signing
test_name="sign"
echo "+++ Starting test $test_name..."

##### Run signing
test_command ${CLI} sign ${KEY_NAME} ${CRED_FILE} ${DATA_FILE} ${SIGNATURE_FILE}

if [[ ${TEST_STATUS} -eq 0 ]]; then
  echo "+++ Success: message was signed."
else
  echo "--- Failure: could not sign message."
  exit 1
fi

#############################################################################
#### Test that verification of a valid signature succeeds
test_name="verify"
echo "+++ Starting test $test_name..."

##### Run verification
test_command ${CLI} verify ${KEY_NAME} ${CRED_FILE} ${DATA_FILE} ${SIGNATURE_FILE}

if [[ ${TEST_STATUS} -eq 0 ]]; then
  echo "+++ Success: signature verified."
else
  echo "--- Failure: could not verify signature."
  exit 1
fi

#############################################################################
#### Test that verification fails with a modified message
test_name="test_verify_fails_with_modified_message"
echo "+++ Starting test ${test_name}..."

MODIFIED_DATA_FILE="$TEST_TMPDIR/modified_example_data.txt"
echo "This is some tampered message to sign." > ${MODIFIED_DATA_FILE}

VERIFY_STDERR="$TEST_TMPDIR/verify_stderr.txt"

##### Run verification against the modified message
test_command ${CLI} verify ${KEY_NAME} ${CRED_FILE} ${MODIFIED_DATA_FILE} ${SIGNATURE_FILE} 2> ${VERIFY_STDERR}
cat ${VERIFY_STDERR} >&2

if [[ ${TEST_STATUS} -eq 1 ]] && grep -q "Signature verification failed" ${VERIFY_STDERR}; then
  echo "+++ Verification failed as expected."
else
  echo "--- Verification succeeded but expected to fail."
  exit 1
fi

#############################################################################
#### Test that offline verification of a valid signature succeeds
test_name="verify-offline"
echo "+++ Starting test $test_name..."

##### Run offline verification
test_command ${CLI} verify-offline "" "" ${DATA_FILE} ${SIGNATURE_FILE} ${PUB_KEY_FILE} ${ALGORITHM}

if [[ ${TEST_STATUS} -eq 0 ]]; then
  echo "+++ Success: signature verified offline."
else
  echo "--- Failure: could not verify signature offline."
  exit 1
fi

#############################################################################
#### Test that offline verification fails with a modified message
test_name="test_verify_offline_fails_with_modified_message"
echo "+++ Starting test ${test_name}..."

VERIFY_STDERR="$TEST_TMPDIR/verify_offline_stderr.txt"

##### Run offline verification against the modified message
test_command ${CLI} verify-offline "" "" ${MODIFIED_DATA_FILE} ${SIGNATURE_FILE} ${PUB_KEY_FILE} ${ALGORITHM} 2> ${VERIFY_STDERR}
cat ${VERIFY_STDERR} >&2

if [[ ${TEST_STATUS} -eq 1 ]] && grep -q "Signature verification failed" ${VERIFY_STDERR}; then
  echo "+++ Offline verification failed as expected."
else
  echo "--- Offline verification succeeded but expected to fail."
  exit 1
fi

