#!/usr/bin/env bash
set -euo pipefail

# The non-root child must be able to execute this binary even when the checkout
# is under a private runner home. Keep the checkout's permissions unchanged.
test_binary=$1
shift
test_dir=$(mktemp -d /tmp/msb-agentd-rlimits.XXXXXX)
trap 'rm -rf "$test_dir"' EXIT

cp -- "$test_binary" "$test_dir/agentd-tests"
chmod 755 "$test_dir" "$test_dir/agentd-tests"

sudo prlimit --memlock=8388608:8388608 -- "$test_dir/agentd-tests" "$@"
