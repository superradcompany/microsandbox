#!/usr/bin/env bash

set -euo pipefail

if (( $# == 0 )); then
  echo "usage: $0 <package>..." >&2
  exit 2
fi

readonly MAX_ATTEMPTS=2
readonly COMMAND_TIMEOUT=120s
readonly RETRY_DELAY=10
APT_OPTIONS=(
  -o Acquire::Retries=3
  -o Acquire::http::Timeout=30
  -o Acquire::https::Timeout=30
  -o Dpkg::Lock::Timeout=30
)

run_apt() {
  local description=$1
  shift

  local attempt
  local status
  for (( attempt = 1; attempt <= MAX_ATTEMPTS; attempt++ )); do
    echo "::group::${description} (attempt ${attempt}/${MAX_ATTEMPTS})"
    if timeout --kill-after=10s "${COMMAND_TIMEOUT}" sudo apt-get "${APT_OPTIONS[@]}" "$@"; then
      status=0
    else
      status=$?
    fi
    echo "::endgroup::"

    if (( status == 0 )); then
      return 0
    fi

    if (( status == 124 || status == 137 )); then
      echo "::warning::${description} exceeded ${COMMAND_TIMEOUT} (exit ${status})"
    else
      echo "::warning::${description} failed with exit ${status}"
    fi

    if (( attempt < MAX_ATTEMPTS )); then
      sleep "${RETRY_DELAY}"
    fi
  done

  echo "::warning::${description} failed after ${MAX_ATTEMPTS} attempts"
  return "${status}"
}

# Hosted-runner package mirrors occasionally stop making progress without
# closing the connection. Bound both phases so one unhealthy runner cannot
# occupy a critical fan-out job until its workflow-level timeout.
# APT normally exits zero when an index download fails and keeps old indexes.
# Require a complete refresh before installing or deciding to use a mirror.
if run_apt "Refresh apt package indexes" update -o APT::Update::Error-Mode=any &&
  run_apt "Install apt packages" install -y "$@"; then
  exit 0
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
fallback_dir=$(mktemp -d)
trap 'sudo rm -rf -- "$fallback_dir"' EXIT
# APT drops privileges to _apt while acquiring indexes.
chmod 755 "$fallback_dir"
python3 "$SCRIPT_DIR/prepare-apt-fallback.py" "$fallback_dir" "$(dpkg --print-architecture)"

# Use the mirror's own indexes, not newer cached candidates from an upstream
# that may have synced ahead of it. System sources, trust and pins stay intact.
APT_OPTIONS+=(
  -o "Dir::Etc::sourcelist=$fallback_dir/sources.list"
  -o "Dir::Etc::sourceparts=$fallback_dir/sources.list.d"
  -o "Dir::State::lists=$fallback_dir/lists"
  -o Dir::Cache::pkgcache=
  -o Dir::Cache::srcpkgcache=
)
run_apt "Refresh fallback package indexes" update -o APT::Update::Error-Mode=any
run_apt "Install apt packages from fallback" install -y "$@"
