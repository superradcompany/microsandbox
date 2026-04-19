#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/apt-common.sh
source "$SCRIPT_DIR/../lib/apt-common.sh"

assert_eq() {
    local actual="$1"
    local expected="$2"
    local message="$3"

    if [[ "$actual" != "$expected" ]]; then
        echo "assertion failed: $message" >&2
        echo "  expected: $expected" >&2
        echo "  actual:   $actual" >&2
        exit 1
    fi
}

assert_eq "$(map_deb_arch x86_64)" "amd64" "x86_64 maps to amd64"
assert_eq "$(map_deb_arch aarch64)" "arm64" "aarch64 maps to arm64"
assert_eq "$(normalize_deb_version v1.2.3 4)" "1.2.3-4" "v-prefixed versions gain revision"
assert_eq "$(normalize_deb_version 1.2.3-2 4)" "1.2.3-2" "existing Debian revisions are preserved"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

template="$tmpdir/control.template"
cat >"$template" <<'EOF'
Package: @PACKAGE@
Version: @VERSION@
EOF

rendered="$(render_template "$template" "@PACKAGE@" "microsandbox" "@VERSION@" "1.2.3-1")"
expected=$'Package: microsandbox\nVersion: 1.2.3-1'
assert_eq "$rendered" "$expected" "template placeholders are rendered"
