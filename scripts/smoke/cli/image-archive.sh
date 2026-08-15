#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
MSB_BIN="${MSB_BIN:-${ROOT_DIR}/build/msb}"
TAG="${MSB_CLI_SMOKE_ARCHIVE_TAG:-msb-archive-smoke:ci}"

if [[ ! -x "$MSB_BIN" ]]; then
  echo "msb binary is not executable: $MSB_BIN" >&2
  exit 1
fi

if ! command -v sha256sum >/dev/null 2>&1; then
  echo "sha256sum is required for image archive smoke tests" >&2
  exit 1
fi

case "$(uname -m)" in
  x86_64) architecture="amd64" ;;
  aarch64 | arm64) architecture="arm64" ;;
  *)
    echo "unsupported smoke-test architecture: $(uname -m)" >&2
    exit 1
    ;;
esac

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

# Build the smallest useful `docker save` fixture locally. The smoke test only
# needs a valid config, manifest, and layer to exercise the CLI archive path;
# constructing them here avoids depending on a privileged Docker socket or a
# registry from self-hosted runners.
mkdir -p "$smoke_root/docker-input/layer" "$smoke_root/layer-root"
printf 'hello from archive\n' > "$smoke_root/layer-root/hello.txt"
tar -cf "$smoke_root/docker-input/layer/layer.tar" -C "$smoke_root/layer-root" hello.txt

layer_digest="$(sha256sum "$smoke_root/docker-input/layer/layer.tar" | awk '{print $1}')"
config_path="$smoke_root/docker-input/config.json"
printf '{"architecture":"%s","os":"linux","config":{"Cmd":["cat","/hello.txt"]},"rootfs":{"type":"layers","diff_ids":["sha256:%s"]}}' \
  "$architecture" "$layer_digest" > "$config_path"

config_digest="$(sha256sum "$config_path" | awk '{print $1}')"
config_name="${config_digest}.json"
mv "$config_path" "$smoke_root/docker-input/$config_name"
printf '[{"Config":"%s","RepoTags":null,"Layers":["layer/layer.tar"]}]' \
  "$config_name" > "$smoke_root/docker-input/manifest.json"

tar -cf "$smoke_root/docker-input.tar" -C "$smoke_root/docker-input" \
  "$config_name" manifest.json layer/layer.tar

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
