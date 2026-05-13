#!/usr/bin/env bash
# bump-version.sh — set the microsandbox release version across every SDK
# manifest in one shot.
#
# Usage:
#   scripts/bump-version.sh <new-version>
#   e.g. scripts/bump-version.sh 0.4.6
#
# Updates:
#   - Cargo.toml (workspace.package.version + path-dep `version = "X.Y.Z"`
#     entries across crates/*/Cargo.toml and sdk/*/Cargo.toml)
#   - sdk/node-ts/package.json (top-level + optionalDependencies versions)
#   - sdk/node-ts/npm/*/package.json (per-platform npm sub-packages)
#   - sdk/go/setup.go (sdkVersion constant; consumed by EnsureInstalled to
#     resolve the GitHub release artefact URL for libmicrosandbox_go_ffi)
#
# Does NOT regenerate Cargo.lock or sdk/node-ts/package-lock.json — run
# `cargo check` and `npm install` afterwards.

set -euo pipefail

NEW="${1:-}"
if [ -z "$NEW" ]; then
  echo "usage: $0 <new-version> (e.g. 0.4.6 or 0.4.6-rc.1)" >&2
  exit 2
fi

if [[ ! "$NEW" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "error: version must be semver (X.Y.Z or X.Y.Z-prerelease)" >&2
  exit 2
fi

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

OLD=$(awk -F'"' '/^version = "/{print $2; exit}' Cargo.toml)
if [ -z "$OLD" ]; then
  echo "error: could not read current version from Cargo.toml" >&2
  exit 1
fi

if [ "$OLD" = "$NEW" ]; then
  echo "version already at ${NEW}, nothing to do"
  exit 0
fi

echo "bumping ${OLD} -> ${NEW}"

# Portable in-place sed (BSD/macOS and GNU/Linux).
inplace() {
  local expr="$1" file="$2"
  sed -i.bak "$expr" "$file"
  rm -- "${file}.bak"
}

# --- Rust: workspace + every path-dep version reference ------------------
while IFS= read -r f; do
  if grep -q "version = \"${OLD}\"" "$f"; then
    inplace "s/version = \"${OLD}\"/version = \"${NEW}\"/g" "$f"
    echo "  updated ${f}"
  fi
done < <(find Cargo.toml crates sdk -name Cargo.toml 2>/dev/null)

# --- Node: package.json files --------------------------------------------
# Top-level + per-platform sub-packages. The blanket "OLD" -> "NEW" inside
# these specific files is safe: they only carry microsandbox versions.
for f in sdk/node-ts/package.json sdk/node-ts/npm/*/package.json; do
  [ -e "$f" ] || continue
  if grep -q "\"${OLD}\"" "$f"; then
    inplace "s/\"${OLD}\"/\"${NEW}\"/g" "$f"
    echo "  updated ${f}"
  fi
done

# --- Go: sdkVersion constant ---------------------------------------------
GO_SETUP="sdk/go/setup.go"
if grep -q "sdkVersion = \"${OLD}\"" "$GO_SETUP"; then
  inplace "s/sdkVersion = \"${OLD}\"/sdkVersion = \"${NEW}\"/" "$GO_SETUP"
  echo "  updated ${GO_SETUP}"
fi

echo
echo "next steps:"
echo "  cargo check                       # regenerate Cargo.lock"
echo "  (cd sdk/node-ts && npm install)   # regenerate package-lock.json"
echo "  git diff                          # review"
