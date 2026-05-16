#!/usr/bin/env bash
# bump-version.sh — set the microsandbox release version across every SDK
# manifest in one shot.
#
# Usage:
#   scripts/bump-version.sh <new-version> [<old-version>]
#   e.g. scripts/bump-version.sh 0.4.6
#        scripts/bump-version.sh 0.4.6 0.4.5   # mop up a partial bump
#
# If <old-version> is omitted, it's auto-detected from the first
# `version = "X.Y.Z"` line in the root Cargo.toml. Pass it explicitly when
# re-running against a tree that's already partway through a bump (e.g. a
# prior run touched Cargo.toml but missed the example manifests).
#
# Updates:
#   - Cargo.toml (workspace.package.version + path-dep `version = "X.Y.Z"`
#     entries across crates/*/Cargo.toml and sdk/*/Cargo.toml)
#   - crates/agentd/Cargo.lock (the agentd sub-workspace ships its own
#     lockfile that the root `cargo check` won't refresh — targeted sed
#     against microsandbox-* entries)
#   - sdk/node-ts/package.json (top-level + optionalDependencies versions)
#   - sdk/node-ts/npm/*/package.json (per-platform npm sub-packages)
#   - sdk/node-ts/native/index.cjs (napi-rs binding loader; pins the
#     expected native package version for runtime mismatch checks)
#   - examples/typescript/*/package.json (microsandbox dep pin in every
#     TypeScript example)
#   - sdk/go/setup.go (sdkVersion constant; consumed by EnsureInstalled to
#     resolve the GitHub release artefact URL for libmicrosandbox_go_ffi)
#
# Cargo.lock entries for workspace-versioned crates are bumped by sed,
# but the script does not do a full cargo-driven regen — run `cargo
# check` afterwards if you also need any dependency-graph changes
# reflected.
#
# Does NOT touch sdk/node-ts/package-lock.json or any example
# package-lock.json. Those carry stale entries pinned at the previous
# release version until release.yml's `refresh-lockfile` job re-resolves
# them against the just-published platform packages and opens a follow-up
# PR. (Text-bumping the lockfile here would make it "look consistent" in
# the bump PR but lie about integrity, which then short-circuits the
# post-publish refresh.)

set -euo pipefail

NEW="${1:-}"
OLD_ARG="${2:-}"
if [ -z "$NEW" ]; then
  echo "usage: $0 <new-version> [<old-version>] (e.g. 0.4.6 or 0.4.6-rc.1)" >&2
  exit 2
fi

semver_re='^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'
if [[ ! "$NEW" =~ $semver_re ]]; then
  echo "error: <new-version> must be semver (X.Y.Z or X.Y.Z-prerelease)" >&2
  exit 2
fi
if [ -n "$OLD_ARG" ] && [[ ! "$OLD_ARG" =~ $semver_re ]]; then
  echo "error: <old-version> must be semver (X.Y.Z or X.Y.Z-prerelease)" >&2
  exit 2
fi

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

if [ -n "$OLD_ARG" ]; then
  OLD="$OLD_ARG"
else
  OLD=$(awk -F'"' '/^version = "/{print $2; exit}' Cargo.toml)
  if [ -z "$OLD" ]; then
    echo "error: could not read current version from Cargo.toml" >&2
    exit 1
  fi
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

# --- Rust: Cargo.lock files ----------------------------------------------
# Bump the workspace-versioned crate entries in both the root workspace
# lockfile and the agentd sub-workspace lockfile. The set of crates to
# touch is discovered from every Cargo.toml under crates/ and sdk/ that
# declares `version.workspace = true` — that's exactly the population
# whose Cargo.lock entries carry the workspace version. External crates
# that happen to share the version string are left untouched. (`cargo
# check` would refresh the root lockfile and is still listed in
# next-steps as the source of truth, but seeding the right value here
# keeps the post-script tree consistent.)
WORKSPACE_CRATES=()
while IFS= read -r toml; do
  if grep -q '^version\.workspace = true' "$toml"; then
    name=$(awk -F'"' '/^name = "/{print $2; exit}' "$toml")
    [ -n "$name" ] && WORKSPACE_CRATES+=("$name")
  fi
done < <(find crates sdk -name Cargo.toml 2>/dev/null)

for f in Cargo.lock crates/agentd/Cargo.lock; do
  [ -f "$f" ] || continue
  changed=0
  for crate in "${WORKSPACE_CRATES[@]}"; do
    if grep -q "^name = \"${crate}\"\$" "$f"; then
      inplace "/^name = \"${crate}\"\$/{n;s/^version = \"${OLD}\"\$/version = \"${NEW}\"/;}" "$f"
      changed=1
    fi
  done
  [ "$changed" -eq 1 ] && echo "  updated ${f}"
done

# --- Node: package.json files --------------------------------------------
# Top-level SDK, per-platform sub-packages, and every TypeScript example.
# The blanket "OLD" -> "NEW" inside these files is safe: each manifest's
# own `version` field is independent (0.1.0 for examples) and never
# coincides with a microsandbox release version.
for f in \
  sdk/node-ts/package.json \
  sdk/node-ts/npm/*/package.json \
  examples/typescript/*/package.json; do
  [ -e "$f" ] || continue
  if grep -q "\"${OLD}\"" "$f"; then
    inplace "s/\"${OLD}\"/\"${NEW}\"/g" "$f"
    echo "  updated ${f}"
  fi
done

# --- Node: napi-rs binding loader ----------------------------------------
# sdk/node-ts/native/index.cjs is generated by napi-rs and embeds the
# expected native-package version (used to trip a runtime mismatch error
# when NAPI_RS_ENFORCE_VERSION_CHECK is set). The file only ever carries
# microsandbox versions, so a blanket bare-X.Y.Z replace is safe.
NATIVE_INDEX="sdk/node-ts/native/index.cjs"
if [ -f "$NATIVE_INDEX" ] && grep -q "${OLD}" "$NATIVE_INDEX"; then
  inplace "s/${OLD//./\\.}/${NEW}/g" "$NATIVE_INDEX"
  echo "  updated ${NATIVE_INDEX}"
fi

# --- Go: sdkVersion constant ---------------------------------------------
GO_SETUP="sdk/go/setup.go"
if [ -f "$GO_SETUP" ] && grep -q "sdkVersion = \"${OLD}\"" "$GO_SETUP"; then
  inplace "s/sdkVersion = \"${OLD}\"/sdkVersion = \"${NEW}\"/" "$GO_SETUP"
  echo "  updated ${GO_SETUP}"
fi

echo
echo "next steps:"
echo "  cargo check    # refresh Cargo.lock against the new manifests"
echo "  git diff       # review"
echo
echo "note: sdk/node-ts/package-lock.json (and the example lockfiles) are"
echo "      left stale on purpose — release.yml's refresh-lockfile job"
echo "      regenerates them against the just-published platform packages"
echo "      and opens a follow-up PR."
