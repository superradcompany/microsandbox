#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
MSB_BIN="${MSB_BIN:-${ROOT_DIR}/build/msb}"
IMAGE="${MSB_CLI_SMOKE_IMAGE:-mirror.gcr.io/library/alpine}"
SANDBOX_NAME="${MSB_CLI_SMOKE_NAME:-ci-splitirq-bind-net}"
TIMEOUT="${MSB_CLI_SMOKE_TIMEOUT:-60s}"

if [[ ! -x "$MSB_BIN" ]]; then
  echo "msb binary is not executable: $MSB_BIN" >&2
  exit 1
fi

if [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
  echo "/dev/kvm must be readable and writable for CLI smoke tests" >&2
  exit 1
fi

smoke_root="$(mktemp -d "${TMPDIR:-/tmp}/msb-cli-smoke.XXXXXX")"
created_home=0

if [[ -z "${MSB_HOME:-}" ]]; then
  MSB_HOME="$(mktemp -d "${TMPDIR:-/tmp}/msb-cli-home.XXXXXX")"
  export MSB_HOME
  created_home=1
fi

cleanup() {
  rm -rf "$smoke_root"
  if [[ "$created_home" -eq 1 ]]; then
    rm -rf "$MSB_HOME"
  fi
}
trap cleanup EXIT

mkdir -p "$smoke_root"/bind-{a,b,c}

export LD_LIBRARY_PATH="$ROOT_DIR/build${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

"$MSB_BIN" run \
  --name "$SANDBOX_NAME" \
  --replace \
  --timeout "$TIMEOUT" \
  -v "$smoke_root/bind-a:/a" \
  -v "$smoke_root/bind-b:/b" \
  -v "$smoke_root/bind-c:/c" \
  "$IMAGE" -- sh -lc 'ip link show eth0 >/dev/null && mountpoint -q /a && mountpoint -q /b && mountpoint -q /c'
