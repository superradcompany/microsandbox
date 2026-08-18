#!/usr/bin/env bash

set -euo pipefail

if (( $# == 0 )); then
  echo "usage: $0 <package>..." >&2
  exit 2
fi

readonly MAX_ATTEMPTS=2
readonly COMMAND_TIMEOUT=120s
readonly RETRY_DELAY=10
readonly APT_OPTIONS=(
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

  echo "::error::${description} failed after ${MAX_ATTEMPTS} attempts"
  return "${status}"
}

# Hosted-runner package mirrors occasionally stop making progress without
# closing the connection. Bound both phases so one unhealthy runner cannot
# occupy a critical fan-out job until its workflow-level timeout.
run_apt "Refresh apt package indexes" update
run_apt "Install apt packages" install -y "$@"
