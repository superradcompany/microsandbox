#!/usr/bin/env bash

set -euo pipefail

if (( $# > 1 )) || [[ $# == 1 && $1 != --finish ]]; then
  echo "usage: $0 [--finish]" >&2
  exit 2
fi

: "${GITHUB_WORKSPACE:?run inside a GitHub Actions workspace}"
: "${RUNNER_WORKSPACE:?run inside a GitHub Actions runner workspace}"
workspace_path=$(realpath -e -- "${GITHUB_WORKSPACE}")
runner_workspace_path=$(realpath -e -- "${RUNNER_WORKSPACE}")
if [[ ${GITHUB_ACTIONS:-} != true || ${workspace_path} != "${GITHUB_WORKSPACE}" ||
      ${workspace_path} != "${runner_workspace_path}/"* || ${workspace_path} == "${HOME}" ]]; then
  echo "::error::refusing cleanup outside a dedicated CI workspace" >&2
  exit 1
fi

echo "::group::runner disk before cleanup"
df -hT / /tmp "${GITHUB_WORKSPACE:-$PWD}" "${RUNNER_WORKSPACE:-$PWD}" || true
echo "::endgroup::"

rm -rf "${GITHUB_WORKSPACE:-$PWD}"/build
rm -rf "${GITHUB_WORKSPACE:-$PWD}"/target
rm -rf "${HOME}/.microsandbox"

# KVM test jobs consume prebuilt artifacts, so their build caches are
# expendable. Reclaim them before unpacking the multi-gigabyte nextest archive.
rm -rf "${HOME}/.cargo/registry" "${HOME}/.cargo/git"
# Go marks downloaded module directories read-only. Restore owner write
# permission on directories before removal; do not follow module symlinks.
if [[ -d "${HOME}/go/pkg/mod" && ! -L "${HOME}/go/pkg/mod" ]]; then
  find -P "${HOME}/go/pkg/mod" -type d -exec chmod u+w {} +
fi
rm -rf "${HOME}/go/pkg/mod" "${HOME}/.cache/go-build"

# Self-hosted x64 runners share one root disk across multiple runner users.
# Clean only old temp directories so active jobs keep their per-test homes.
# Keep this unprivileged and limited to the current runner user's files.
# 'msb*' not 'msb-*': tests also leave hyphen-less dirs (msbperf,
# msbtest1128, msbunmount) that a 'msb-*' glob never reclaims (#1162).
find /tmp -mindepth 1 -maxdepth 1 -type d \
  -uid "$(id -u)" \
  \( -name 'msb*' -o -name 'TestSandbox*' -o -name 'go-build*' -o -name 'cbh-*' -o -name 'nextest-archive-*' \) \
  -mmin +120 -exec rm -rf {} + 2>/dev/null || true

find /tmp -mindepth 1 -maxdepth 1 -type d \
  -uid "$(id -u)" \
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

# This is admission headroom, not a reservation against other runner users.
# End-of-job cleanup must not turn a passing test into a disk-admission failure.
python3 "$(dirname "$0")/runner-storage.py" "$@"
