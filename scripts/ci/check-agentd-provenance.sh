#!/usr/bin/env bash
# Regression check for the guest-agent provenance policy in
# crates/filesystem/build.rs.
#
# `agentd` is compiled into the host binary, so embedding an artifact that does
# not belong to this tree changes guest-side behaviour without failing anything
# else. The policy is therefore: a checkout always embeds its own build/agentd,
# and fails when that artifact is stale or missing, while a build with no guest
# source tree at all - a published crate - may embed the released artifact.
#
# The interesting cases are failures, so each one asserts the message a developer
# needs, not merely a non-zero exit. The consumer-side branches (released
# download, reused OUT_DIR copy) cannot be exercised from inside the repository;
# they are covered by the probe described in the commit that added this script.
#
# Everything this script moves or touches is restored on exit, including the
# original mtimes of the guest sources and of the artifact: a check that leaves a
# stale artifact looking fresh would hide the very defect it reports.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."

readonly AGENTD=build/agentd

scratch="$(mktemp -d "${TMPDIR:-/tmp}/microsandbox-agentd-provenance.XXXXXX")"
readonly SCRATCH="$scratch"
readonly EXPLICIT="$SCRATCH/agentd"
readonly ARTIFACTS="$SCRATCH/artifacts"
readonly BACKUP="$SCRATCH/agentd.backup"
readonly ORIGINAL="$SCRATCH/agentd.original"
readonly SOURCES="$SCRATCH/sources"
moved=false

cleanup() {
  if [[ "$moved" == true ]]; then
    mv -f "$BACKUP" "$AGENTD"
    moved=false
  fi
  # `cp -p` restores the bytes and the original mtime, so an artifact that was
  # stale when the script started is still stale when it ends.
  if [[ -f "$ORIGINAL" ]]; then
    cp -p "$ORIGINAL" "$AGENTD"
  fi
  restore_source_mtimes
  rm -rf "$SCRATCH"
}
trap cleanup EXIT

# Restore the mtimes the staleness cases changed, so the checkout is left as it
# was found. The snapshot is taken before any case runs and keeps the contents
# too, so a file deleted by a case comes back with its original timestamp.
restore_source_mtimes() {
  local tree rel
  [[ -d "$SOURCES" ]] || return 0
  for tree in agentd protocol; do
    while IFS= read -r rel; do
      touch -r "$SOURCES/$tree/${rel#./}" "crates/$tree/${rel#./}"
    done < <(cd "$SOURCES/$tree" && find . -type f)
  done
}

if [[ ! -f "$AGENTD" ]]; then
  echo "agentd provenance: SKIP: no $AGENTD (build it with 'just build-agentd')"
  exit 0
fi

cp -p "$AGENTD" "$ORIGINAL"
mkdir -p "$SOURCES"
cp -pR crates/agentd "$SOURCES/agentd"
cp -pR crates/protocol "$SOURCES/protocol"
cp "$AGENTD" "$EXPLICIT"
mkdir -p "$ARTIFACTS"
cp "$AGENTD" "$ARTIFACTS/agentd"

fail() {
  echo "agentd provenance: FAIL: $*" >&2
  exit 1
}

# Only the filesystem crate is needed: it owns the build script under test.
check_default() {
  env -u MSB_EMBED_ARTIFACTS_DIR -u MSB_EMBED_AGENTD_PATH \
    cargo check -p microsandbox-filesystem --lib 2>&1
}

check_explicit_artifacts_dir() {
  env -u MSB_EMBED_AGENTD_PATH MSB_EMBED_ARTIFACTS_DIR="$ARTIFACTS" \
    cargo check -p microsandbox-filesystem --lib 2>&1
}

check_explicit_agentd_path() {
  env -u MSB_EMBED_ARTIFACTS_DIR MSB_EMBED_AGENTD_PATH="$EXPLICIT" \
    cargo check -p microsandbox-filesystem --lib 2>&1
}

# The runtime override resolves against the caller's working directory, so a
# relative value like this one is valid for `msb` at startup. It must not reach
# the build, which resolves paths against the package directory instead.
check_runtime_override_ignored() {
  env -u MSB_EMBED_ARTIFACTS_DIR MSB_AGENTD_PATH=build/agentd \
    cargo check -p microsandbox-filesystem --lib 2>&1
}

# Without `download-binaries` the local artifact is the only supported source, so
# the released artifact can never stand in for it.
check_without_downloads() {
  env -u MSB_EMBED_ARTIFACTS_DIR -u MSB_EMBED_AGENTD_PATH \
    cargo check -p microsandbox-filesystem --lib --no-default-features \
    --features embed-binaries 2>&1
}

# The staleness check compares the newest mtime in the guest source tree against
# the artifact, so refreshing every file is the honest way to make it stale. It
# also dirties the build script: Cargo decides freshness from input mtimes, so an
# older artifact alone would not rerun the script under test.
mark_sources_newer_than_artifact() {
  find crates/agentd crates/protocol -type f -exec touch {} +
}

mark_artifact_newer_than_sources() {
  touch "$AGENTD"
}

remove_artifact() {
  mv -f "$AGENTD" "$BACKUP"
  moved=true
}

restore_artifact() {
  if [[ "$moved" == true ]]; then
    mv -f "$BACKUP" "$AGENTD"
    moved=false
  fi
}

# Assert that a build fails, and that its message names everything the developer
# needs. The check comes first and every argument after it is a required
# substring of the same failure output, so one run can assert a whole remedy.
expect_failure() {
  local description="$1" check="$2"
  shift 2
  local output="" expected=""

  if output="$("$check" 2>&1)"; then
    fail "$description: the build succeeded, but it must not"
  fi
  for expected in "$@"; do
    if ! grep -qF -- "$expected" <<<"$output"; then
      printf '%s\n' "$output" >&2
      fail "$description: the failure does not mention: $expected"
    fi
  done
  echo "ok: $description"
}

expect_success() {
  local description="$1"
  shift

  if ! "$@" >/dev/null 2>&1; then
    fail "$description: the build failed, but it must not"
  fi
  echo "ok: $description"
}

expect_success_mentioning() {
  local description="$1" expected="$2"
  shift 2
  local output=""

  if ! output="$("$@" 2>&1)"; then
    fail "$description: the build failed, but it must not"
  fi
  if ! grep -qF -- "$expected" <<<"$output"; then
    printf '%s\n' "$output" >&2
    fail "$description: the build does not mention: $expected"
  fi
  echo "ok: $description"
}

# A current local artifact is the normal case and must stay quiet.
mark_artifact_newer_than_sources
expect_success "fresh build/agentd is embedded" check_default

# An environment that points `msb` at a runtime agentd must keep building: the
# runtime variable resolves against the caller's working directory, so a value
# like `build/agentd` is legitimate there and must not reach the build.
mark_artifact_newer_than_sources
expect_success \
  "a runtime MSB_AGENTD_PATH is ignored by the build" \
  check_runtime_override_ignored

# Embedding an artifact older than the guest sources is the defect this policy
# exists to catch: it changes guest behaviour with nothing else failing.
mark_sources_newer_than_artifact
expect_failure \
  "a stale build/agentd fails instead of being embedded" \
  check_default \
  "is older than crates/agentd or crates/protocol source"

# The released-artifact fallback must not be what makes staleness observable, so
# the refusal is unconditional on the download feature.
expect_failure \
  "a stale build/agentd fails without the download feature too" \
  check_without_downloads \
  "is older than crates/agentd or crates/protocol source"

# A checkout can always rebuild the guest agent, so it must never substitute the
# released artifact for a missing local one. Both ways to produce it are named:
# the vendored recipe needs `just` and, on macOS, Docker, so a host that has
# neither needs the cross-build to be in the message too.
# A checkout that has never built the guest agent must be refused, and the
# remedy must name a build that targets the guest: a plain host `cargo build`
# produces a payload this build rejects, so the `--target` is asserted too.
mark_artifact_newer_than_sources
remove_artifact
expect_failure \
  "a missing build/agentd in a checkout fails instead of downloading the release" \
  check_default \
  "will not embed a released agentd" \
  "just build-agentd" \
  "cargo build --release" \
  "-unknown-linux-musl" \
  "--manifest-path crates/agentd/Cargo.toml"

expect_failure \
  "a missing build/agentd fails without the download feature too" \
  check_without_downloads \
  "will not embed a released agentd"

# An explicit artifact is the caller's choice, and says so. The build-time
# override is its own name, so a runtime MSB_AGENTD_PATH cannot reach the build.
expect_success_mentioning \
  "MSB_EMBED_AGENTD_PATH is embedded when build/agentd is missing" \
  "embedding the guest agent from MSB_EMBED_AGENTD_PATH=$EXPLICIT" \
  check_explicit_agentd_path

expect_success \
  "MSB_EMBED_ARTIFACTS_DIR is embedded when build/agentd is missing" \
  check_explicit_artifacts_dir

# ... and an explicit artifact beats a stale local one rather than failing on it.
restore_artifact
mark_sources_newer_than_artifact
expect_success_mentioning \
  "MSB_EMBED_AGENTD_PATH is embedded even when build/agentd is stale" \
  "embedding the guest agent from MSB_EMBED_AGENTD_PATH=$EXPLICIT" \
  check_explicit_agentd_path

mark_artifact_newer_than_sources

echo "agentd provenance: OK"
