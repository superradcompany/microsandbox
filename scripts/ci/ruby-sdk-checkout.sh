#!/usr/bin/env bash

set -euo pipefail

operation=${1:-}
ruby_cargo_home="${RUNNER_TEMP:?}/microsandbox-ruby-cargo"
standalone_lock="${RUNNER_TEMP}/microsandbox-ruby-standalone.lock"
extension_lock="${GITHUB_WORKSPACE:?}/sdk/ruby/ext/microsandbox/Cargo.lock"

case "$operation" in
  prepare)
    mkdir -p "$ruby_cargo_home"
    printf '[patch.crates-io]\nmicrosandbox = { path = "%s/sdk/rust" }\n' \
      "$GITHUB_WORKSPACE" > "$ruby_cargo_home/config.toml"
    mv "$extension_lock" "$standalone_lock"
    cp "$GITHUB_WORKSPACE/Cargo.lock" "$extension_lock"
    echo "CARGO_HOME=$ruby_cargo_home" >> "${GITHUB_ENV:?}"
    echo "MICROSANDBOX_RUBY_STANDALONE_LOCK=$standalone_lock" >> "$GITHUB_ENV"
    ;;
  restore)
    if [[ -f "$standalone_lock" ]]; then
      mv "$standalone_lock" "$extension_lock"
    fi
    ;;
  *)
    echo "usage: $0 {prepare|restore}" >&2
    exit 2
    ;;
esac
