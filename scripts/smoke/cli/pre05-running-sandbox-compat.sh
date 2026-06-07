#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
MSB_BIN="${MSB_BIN:-${ROOT_DIR}/build/msb}"
OLD_VERSION="${MSB_PRE05_COMPAT_VERSION:-v0.4.6}"
IMAGE="${MSB_PRE05_COMPAT_IMAGE:-mirror.gcr.io/library/alpine}"
SANDBOX_NAME="${MSB_PRE05_COMPAT_NAME:-msb05compat}"
REPO="${MSB_PRE05_COMPAT_REPO:-superradcompany/microsandbox}"

if [[ ! -x "$MSB_BIN" ]]; then
  echo "msb binary is not executable: $MSB_BIN" >&2
  exit 1
fi

case "$(uname -s)" in
  Darwin)
    os="darwin"
    lib_name="libkrunfw.5.dylib"
    ;;
  Linux)
    os="linux"
    lib_name="libkrunfw.so.5"
    if [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
      echo "/dev/kvm must be readable and writable for CLI smoke tests" >&2
      exit 1
    fi
    ;;
  *)
    echo "unsupported OS: $(uname -s)" >&2
    exit 1
    ;;
esac

case "$(uname -m)" in
  arm64 | aarch64)
    arch="aarch64"
    ;;
  x86_64 | amd64)
    arch="x86_64"
    ;;
  *)
    echo "unsupported architecture: $(uname -m)" >&2
    exit 1
    ;;
esac

smoke_root="$(mktemp -d "/tmp/msb05.XXXXXX")"
old_bin_dir="$smoke_root/old-release"
export MSB_HOME="$smoke_root/home"

download_asset() {
  local asset="$1"
  local dest="$2"
  local url="https://github.com/${REPO}/releases/download/${OLD_VERSION}/${asset}"

  if command -v gh >/dev/null 2>&1; then
    gh release download "$OLD_VERSION" --repo "$REPO" --pattern "$asset" --dir "$old_bin_dir" --clobber
    mv "$old_bin_dir/$asset" "$dest"
  else
    curl -fsSL "$url" -o "$dest"
  fi
}

cleanup() {
  if [[ -n "${old_msb:-}" && -x "${old_msb:-}" ]]; then
    MSB_HOME="$MSB_HOME" "$old_msb" stop "$SANDBOX_NAME" --quiet >/dev/null 2>&1 || true
    MSB_HOME="$MSB_HOME" "$old_msb" remove "$SANDBOX_NAME" --quiet >/dev/null 2>&1 || true
  fi
  rm -rf "$smoke_root"
}
trap cleanup EXIT

mkdir -p "$old_bin_dir" "$MSB_HOME/bin" "$MSB_HOME/lib"

old_msb="$old_bin_dir/msb"
download_asset "msb-${os}-${arch}" "$old_msb"
download_asset "agentd-${arch}" "$MSB_HOME/bin/agentd"
download_asset "libkrunfw-${os}-${arch}.$([[ "$os" == "darwin" ]] && echo dylib || echo so)" "$MSB_HOME/lib/$lib_name"
chmod +x "$old_msb" "$MSB_HOME/bin/agentd"

if [[ "$os" == "darwin" ]]; then
  ln -sf "$lib_name" "$MSB_HOME/lib/libkrunfw.dylib"
else
  ln -sf "$lib_name" "$MSB_HOME/lib/libkrunfw.so"
fi

MSB_HOME="$MSB_HOME" "$old_msb" create \
  --name "$SANDBOX_NAME" \
  --replace \
  --memory 512M \
  --pull if-missing \
  --quiet \
  "$IMAGE"

output="$(
  MSB_HOME="$MSB_HOME" "$MSB_BIN" --warn exec "$SANDBOX_NAME" -- \
    sh -lc 'printf "pre05-compat:%s:%s\n" "$(sed -n "s/^ID=//p" /etc/os-release)" "$(uname -m)"' \
    2>&1
)"

printf '%s\n' "$output"
grep -q 'pre05-compat:alpine:' <<<"$output"
grep -q 'started before microsandbox 0.5' <<<"$output"
