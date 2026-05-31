#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
MSB_BIN="${MSB_BIN:-${ROOT_DIR}/build/msb}"
IMAGE="${MSB_CLI_SMOKE_DOCKER_IMAGE:-alpine:3.20}"
TAG="${MSB_CLI_SMOKE_ARCHIVE_TAG:-msb-archive-smoke:ci}"

if [[ ! -x "$MSB_BIN" ]]; then
  echo "msb binary is not executable: $MSB_BIN" >&2
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required for image archive smoke tests" >&2
  exit 1
fi

smoke_root="$(mktemp -d "${TMPDIR:-/tmp}/msb-image-archive-smoke.XXXXXX")"
created_home=0

if [[ -z "${MSB_HOME:-}" ]]; then
  MSB_HOME="$(mktemp -d "${TMPDIR:-/tmp}/msb-image-archive-home.XXXXXX")"
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

docker image inspect "$IMAGE" >/dev/null 2>&1 || docker pull "$IMAGE" >/dev/null
docker save "$IMAGE" -o "$smoke_root/docker-input.tar"

"$MSB_BIN" load -i "$smoke_root/docker-input.tar" --tag "$TAG" --quiet
"$MSB_BIN" save -o "$smoke_root/docker-output.tar" --quiet "$TAG"
"$MSB_BIN" save --format oci -o "$smoke_root/oci-output.tar" --quiet "$TAG"

tar -tf "$smoke_root/docker-output.tar" > "$smoke_root/docker-entries.txt"
grep -qx 'manifest.json' "$smoke_root/docker-entries.txt"
grep -q '/layer.tar$' "$smoke_root/docker-entries.txt"

tar -tf "$smoke_root/oci-output.tar" > "$smoke_root/oci-entries.txt"
grep -qx 'oci-layout' "$smoke_root/oci-entries.txt"
grep -qx 'index.json' "$smoke_root/oci-entries.txt"
grep -q '^blobs/sha256/' "$smoke_root/oci-entries.txt"

MSB_HOME="$smoke_root/reload-home" "$MSB_BIN" load -i "$smoke_root/oci-output.tar" --quiet
MSB_HOME="$smoke_root/reload-home" "$MSB_BIN" images -q | grep -qx "$TAG"
