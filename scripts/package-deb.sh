#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: scripts/package-deb.sh --arch <arch> --version <version> --msb <path> \
  --libkrunfw <path> --output-dir <dir> [--package <name>] [--revision <n>]

Build a Debian package for microsandbox from Linux release artifacts.
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
    local revision="$2"
    local clean="${raw#v}"

    if [[ "$clean" == *-* ]]; then
        printf '%s\n' "$clean"
        return
    fi

    printf '%s-%s\n' "$clean" "$revision"
}

render_template() {
    local template="$1"
    shift

    local rendered
    rendered="$(<"$template")"

    while [[ $# -gt 0 ]]; do
        local key="$1"
        local value="$2"
        rendered="${rendered//${key}/${value}}"
        shift 2
    done

    printf '%s' "$rendered"
}

PACKAGE_NAME="microsandbox"
ARCH=""
VERSION=""
REVISION="1"
MSB_PATH=""
LIBKRUNFW_PATH=""
OUTPUT_DIR=""

while [[ $# -gt 0 ]]; do
    case "$1" in
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
        --msb)
            MSB_PATH="$2"
            shift 2
            ;;
        --libkrunfw)
            LIBKRUNFW_PATH="$2"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --package)
            PACKAGE_NAME="$2"
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

[[ -n "$ARCH" && -n "$VERSION" && -n "$MSB_PATH" && -n "$LIBKRUNFW_PATH" && -n "$OUTPUT_DIR" ]] || {
    usage >&2
    exit 1
}

require_cmd dpkg-deb
require_cmd dpkg-shlibdeps
require_cmd gzip
require_cmd sed

[[ -f "$MSB_PATH" ]] || {
    echo "error: msb binary not found: $MSB_PATH" >&2
    exit 1
}
[[ -f "$LIBKRUNFW_PATH" ]] || {
    echo "error: libkrunfw library not found: $LIBKRUNFW_PATH" >&2
    exit 1
}

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPLATE_DIR="$REPO_ROOT/packaging/apt"
DEB_ARCH="$(map_deb_arch "$ARCH")"
DEB_VERSION="$(normalize_version "$VERSION" "$REVISION")"
LIBKRUNFW_BASENAME="$(basename "$LIBKRUNFW_PATH")"
if [[ "$LIBKRUNFW_BASENAME" =~ ^libkrunfw\.so\.([0-9]+)\..+$ ]]; then
    LIBKRUNFW_ABI="${BASH_REMATCH[1]}"
else
    echo "error: unsupported libkrunfw filename: $LIBKRUNFW_BASENAME" >&2
    exit 1
fi
LIBKRUNFW_SONAME_LINK="libkrunfw.so.$LIBKRUNFW_ABI"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$REPO_ROOT" log -1 --format=%ct 2>/dev/null || date +%s)}"

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

PACKAGE_ROOT="$WORK_DIR/package"
DEBIAN_DIR="$PACKAGE_ROOT/DEBIAN"
DEBIAN_HELPER_DIR="$WORK_DIR/debian"
DOC_DIR="$PACKAGE_ROOT/usr/share/doc/$PACKAGE_NAME"
BIN_DIR="$PACKAGE_ROOT/usr/bin"
LIB_DIR="$PACKAGE_ROOT/usr/lib/microsandbox"

mkdir -p "$DEBIAN_DIR" "$DEBIAN_HELPER_DIR" "$DOC_DIR" "$BIN_DIR" "$LIB_DIR"

install -m755 "$MSB_PATH" "$BIN_DIR/msb"
install -m644 "$LIBKRUNFW_PATH" "$LIB_DIR/$LIBKRUNFW_BASENAME"
ln -s "$LIBKRUNFW_BASENAME" "$LIB_DIR/$LIBKRUNFW_SONAME_LINK"
ln -s "$LIBKRUNFW_SONAME_LINK" "$LIB_DIR/libkrunfw.so"

install -m644 "$TEMPLATE_DIR/copyright" "$DOC_DIR/copyright"

CHANGELOG_DATE="$(date -Ru -d "@$SOURCE_DATE_EPOCH")"
cat >"$DOC_DIR/changelog.Debian" <<EOF
$PACKAGE_NAME ($DEB_VERSION) stable; urgency=medium

  * Publish the microsandbox CLI and bundled libkrunfw runtime library.

 -- Super Rad Company <development@superrad.company>  $CHANGELOG_DATE
EOF
gzip -n9 "$DOC_DIR/changelog.Debian"
chmod 644 "$DOC_DIR/changelog.Debian.gz"
find "$PACKAGE_ROOT" -type d -exec chmod 755 {} +

while IFS= read -r -d '' path; do
    touch -h -d "@$SOURCE_DATE_EPOCH" "$path"
done < <(find "$PACKAGE_ROOT" -print0)

cat >"$DEBIAN_HELPER_DIR/control" <<EOF
Source: $PACKAGE_NAME
Section: utils
Priority: optional
Maintainer: Super Rad Company <development@superrad.company>
Standards-Version: 4.7.0

Package: $PACKAGE_NAME
Architecture: $DEB_ARCH
Description: Lightweight microVM sandbox CLI
 Microsandbox spins up lightweight, hardware-isolated microVMs from a local
 CLI. This package installs the \`msb\` command and the private \`libkrunfw\`
 runtime library used to boot and manage microsandbox environments on Debian
 and Ubuntu systems.
EOF

cat >"$DEBIAN_DIR/shlibs" <<EOF
libkrunfw $LIBKRUNFW_ABI $PACKAGE_NAME (= $DEB_VERSION)
EOF

SHLIBS_DEPENDS="$(
    cd "$WORK_DIR"
    dpkg-shlibdeps \
        -O \
        -Tdebian/substvars \
        -S"$PACKAGE_ROOT" \
        -l"$LIB_DIR" \
        "$BIN_DIR/msb" \
        "$LIB_DIR/$LIBKRUNFW_BASENAME" | sed -n 's/^shlibs:Depends=//p'
)"

[[ -n "$SHLIBS_DEPENDS" ]] || {
    echo "error: failed to derive package dependencies with dpkg-shlibdeps" >&2
    exit 1
}

rm -f "$DEBIAN_DIR/shlibs"

INSTALLED_SIZE="$(du -sk "$PACKAGE_ROOT" | cut -f1)"

render_template \
    "$TEMPLATE_DIR/control.template" \
    "@PACKAGE@" "$PACKAGE_NAME" \
    "@VERSION@" "$DEB_VERSION" \
    "@ARCH@" "$DEB_ARCH" \
    "@INSTALLED_SIZE@" "$INSTALLED_SIZE" \
    "@DEPENDS@" "$SHLIBS_DEPENDS" >"$DEBIAN_DIR/control"
printf '\n' >>"$DEBIAN_DIR/control"

mkdir -p "$OUTPUT_DIR"
OUTPUT_PATH="$OUTPUT_DIR/${PACKAGE_NAME}_${DEB_VERSION}_${DEB_ARCH}.deb"
dpkg-deb --root-owner-group --uniform-compression -Zxz --build "$PACKAGE_ROOT" "$OUTPUT_PATH" >/dev/null

printf '%s\n' "$OUTPUT_PATH"
