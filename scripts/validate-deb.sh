#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: scripts/validate-deb.sh --deb <path> --arch <arch> --version <version>

Run structural validation and lint checks for a microsandbox Debian package.
EOF
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "error: required command not found: $1" >&2
        exit 1
    }
}

map_deb_arch() {
    case "$1" in
        amd64 | x86_64) echo "amd64" ;;
        arm64 | aarch64) echo "arm64" ;;
        *)
            echo "error: unsupported Debian architecture: $1" >&2
            exit 1
            ;;
    esac
}

normalize_version() {
    local raw="$1"
    local revision="${2:-1}"
    local clean="${raw#v}"
    if [[ "$clean" == *-* ]]; then
        printf '%s\n' "$clean"
    else
        printf '%s-%s\n' "$clean" "$revision"
    fi
}

DEB_PATH=""
ARCH=""
VERSION=""
REVISION="1"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --deb)
            DEB_PATH="$2"
            shift 2
            ;;
        --arch)
            ARCH="$2"
            shift 2
            ;;
        --version)
            VERSION="$2"
            shift 2
            ;;
        --revision)
            REVISION="$2"
            shift 2
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            echo "error: unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

[[ -n "$DEB_PATH" && -n "$ARCH" && -n "$VERSION" ]] || {
    usage >&2
    exit 1
}

require_cmd dpkg-deb
require_cmd lintian
require_cmd tar
require_cmd readlink

[[ -f "$DEB_PATH" ]] || {
    echo "error: package not found: $DEB_PATH" >&2
    exit 1
}

EXPECTED_ARCH="$(map_deb_arch "$ARCH")"
EXPECTED_VERSION="$(normalize_version "$VERSION" "$REVISION")"

[[ "$(dpkg-deb -f "$DEB_PATH" Package)" == "microsandbox" ]]
[[ "$(dpkg-deb -f "$DEB_PATH" Architecture)" == "$EXPECTED_ARCH" ]]
[[ "$(dpkg-deb -f "$DEB_PATH" Version)" == "$EXPECTED_VERSION" ]]

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

dpkg-deb -x "$DEB_PATH" "$TMP_DIR/root"

[[ -x "$TMP_DIR/root/usr/bin/msb" ]]
[[ -d "$TMP_DIR/root/usr/lib/microsandbox" ]]

mapfile -t VERSIONED_LIBS < <(find "$TMP_DIR/root/usr/lib/microsandbox" \
    -maxdepth 1 -type f -name 'libkrunfw.so.*' | sort)
[[ ${#VERSIONED_LIBS[@]} -eq 1 ]]

VERSIONED_LIB_BASENAME="$(basename "${VERSIONED_LIBS[0]}")"
if [[ "$VERSIONED_LIB_BASENAME" =~ ^libkrunfw\.so\.([0-9]+)\..+$ ]]; then
    LIBKRUNFW_SONAME_LINK="libkrunfw.so.${BASH_REMATCH[1]}"
else
    echo "error: unsupported libkrunfw filename in package: $VERSIONED_LIB_BASENAME" >&2
    exit 1
fi

[[ -L "$TMP_DIR/root/usr/lib/microsandbox/$LIBKRUNFW_SONAME_LINK" ]]
[[ -L "$TMP_DIR/root/usr/lib/microsandbox/libkrunfw.so" ]]
[[ "$(readlink "$TMP_DIR/root/usr/lib/microsandbox/$LIBKRUNFW_SONAME_LINK")" == "$VERSIONED_LIB_BASENAME" ]]
[[ "$(readlink "$TMP_DIR/root/usr/lib/microsandbox/libkrunfw.so")" == "$LIBKRUNFW_SONAME_LINK" ]]

[[ -f "$TMP_DIR/root/usr/share/doc/microsandbox/copyright" ]]
[[ -f "$TMP_DIR/root/usr/share/doc/microsandbox/changelog.Debian.gz" ]]

[[ ! -e "$TMP_DIR/root/root/.microsandbox" ]]
[[ ! -e "$TMP_DIR/root/etc/profile.d/microsandbox.sh" ]]
[[ ! -e "$TMP_DIR/root/etc/bash.bashrc" ]]
[[ ! -e "$TMP_DIR/root/etc/skel/.bashrc" ]]
[[ ! -e "$TMP_DIR/root/usr/share/fish/vendor_conf.d/microsandbox.fish" ]]

CONTROL_LIST="$(dpkg-deb --ctrl-tarfile "$DEB_PATH" | tar -tf -)"
for forbidden in preinst postinst prerm postrm triggers; do
    if grep -Eq "(^|/)$forbidden$" <<<"$CONTROL_LIST"; then
        echo "error: unexpected maintainer script present: $forbidden" >&2
        exit 1
    fi
done

dpkg-deb --info "$DEB_PATH" >/dev/null
dpkg-deb --contents "$DEB_PATH" >/dev/null
lintian --fail-on error "$DEB_PATH"
