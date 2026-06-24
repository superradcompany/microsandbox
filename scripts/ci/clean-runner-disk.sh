#!/usr/bin/env bash

set -euo pipefail

echo "::group::runner disk before cleanup"
df -hT / /tmp "${GITHUB_WORKSPACE:-$PWD}" "${RUNNER_WORKSPACE:-$PWD}" || true
echo "::endgroup::"

rm -rf "${GITHUB_WORKSPACE:-$PWD}"/build
rm -rf "${GITHUB_WORKSPACE:-$PWD}"/target
rm -rf "${HOME}/.microsandbox"

# Self-hosted x64 runners share one root disk across multiple runner users.
# Clean only old temp directories so active jobs keep their per-test homes.
# The runner sudoers policy only permits apt-get, so keep this best-effort and
# limited to paths the current runner user can remove.
find /tmp -mindepth 1 -maxdepth 1 -type d \
  \( -name 'msb-*' -o -name 'TestSandbox*' -o -name 'go-build*' \) \
  -mmin +120 -exec rm -rf {} + 2>/dev/null || true

find /tmp -mindepth 1 -maxdepth 1 -type d \
  \( -name 'codex-*' -o -name 'microsandbox-*' -o -name 'libkrun-*' \) \
  -mmin +360 -exec rm -rf {} + 2>/dev/null || true

# Prune stale sibling checkouts left by previous runs, but never the one the
# current job runs from. $GITHUB_WORKSPACE lives directly under
# $RUNNER_WORKSPACE and matches 'microsandbox*', and a git checkout that
# doesn't add or remove top-level entries leaves the directory's own mtime
# untouched, so the -mmin guard alone would let this find delete the live
# working directory mid-job (the next step then fails with "No such file or
# directory" on its working directory).
if [[ -n "${RUNNER_WORKSPACE:-}" && -d "${RUNNER_WORKSPACE}" ]]; then
  find "${RUNNER_WORKSPACE}" -mindepth 1 -maxdepth 1 -type d \
    -name 'microsandbox*' \
    ! -path "${GITHUB_WORKSPACE:-/nonexistent}" \
    -mmin +360 -exec rm -rf {} + 2>/dev/null || true
fi

echo "::group::runner disk after cleanup"
df -hT / /tmp "${GITHUB_WORKSPACE:-$PWD}" "${RUNNER_WORKSPACE:-$PWD}" || true
du -xhd1 /tmp 2>/dev/null | sort -h | tail -30 || true
echo "::endgroup::"
