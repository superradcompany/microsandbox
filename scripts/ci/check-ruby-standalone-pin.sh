#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$script_dir/../../sdk/ruby/ext/microsandbox"

pin="$(sed -nE 's/.*package = "microsandbox", version = "=([^"]+)".*/\1/p' Cargo.toml)"
if [ -z "$pin" ]; then
  echo "::error::could not read the exact microsandbox pin from sdk/ruby/ext/microsandbox/Cargo.toml"
  exit 1
fi

status="$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
  --header 'User-Agent: microsandbox-ci (https://github.com/superradcompany/microsandbox)' \
  "https://crates.io/api/v1/crates/microsandbox/$pin")"
case "$status" in
  200)
    echo "microsandbox $pin is published on crates.io"
    ;;
  404)
    echo "::notice::microsandbox $pin is not on crates.io yet; skipping standalone pin check"
    exit 0
    ;;
  *)
    echo "::error::crates.io returned HTTP $status for microsandbox $pin"
    exit 1
    ;;
esac

cargo fetch --locked
