#! /bin/bash
# 
# Copyright (c) 2026 SoftHSMv2 contributors
#
# SPDX-License-Identifier: BSD-2-Clause
#

CI_TEST_ENABLED="${MLDSA_TEST}"
ALGO_NAME="ML-DSA"
OPENSSL_ALGO="ML-DSA-44"
TOKEN_DIR_NAME="tokens-mldsa-44"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/import-key-test-common.sh"