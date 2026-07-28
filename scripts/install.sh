#!/bin/sh
# Microsandbox installer
# Usage: curl -fsSL https://install.microsandbox.dev | sh
set -eu

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

GITHUB_REPO="superradcompany/microsandbox"
INSTALL_DIR="${MSB_HOME:-$HOME/.microsandbox}"
BIN_DIR="$INSTALL_DIR/bin"
LIB_DIR="$INSTALL_DIR/lib"
LOCAL_BIN_DIR="$HOME/.local/bin"

# Current Linux release bundles are built on GitHub Actions ubuntu-latest,
# which currently maps to Ubuntu 24.04 (glibc 2.39).
LINUX_GLIBC_MIN_VERSION="2.39"

# Progress bar
BAR_WIDTH=40

# Colors (disabled if not a terminal)
if [ -t 1 ]; then
    BOLD='\033[1m'
    DIM='\033[2m'
    GREEN='\033[0;32m'
    CYAN='\033[0;36m'
    RED='\033[0;31m'
    YELLOW='\033[0;33m'
    RESET='\033[0m'
else
    BOLD=''
    DIM=''
    GREEN=''
    CYAN=''
    RED=''
    YELLOW=''
    RESET=''
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

info() {
    printf "${BOLD}${CYAN}info${RESET} %s\n" "$1"
}

success() {
    printf "${BOLD}${GREEN}done${RESET} %s\n" "$1"
}

warn() {
    printf "${BOLD}${YELLOW}warn${RESET} %s\n" "$1"
}

error() {
    printf "${BOLD}${RED}error${RESET} %s\n" "$1" >&2
    exit 1
}

need_cmd() {
    if ! command -v "$1" > /dev/null 2>&1; then
        error "required command not found: $1"
    fi
}

resolve_libkrunfw_artifact() {
    if [ "$OS" = "linux" ]; then
        # The full version belongs to the release artifact, so discover it
        # after extraction instead of keeping another version pin here.
        set -- libkrunfw.so.*.*.*
        if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
            error "release bundle must contain exactly one versioned libkrunfw shared library"
        fi

        LIBKRUNFW_FILE=$1
        _libkrunfw_version=${LIBKRUNFW_FILE#libkrunfw.so.}
        LIBKRUNFW_ABI=${_libkrunfw_version%%.*}
    elif [ "$OS" = "darwin" ]; then
        set -- libkrunfw.*.dylib
        if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
            error "release bundle must contain exactly one versioned libkrunfw shared library"
        fi

        LIBKRUNFW_FILE=$1
        LIBKRUNFW_ABI=${LIBKRUNFW_FILE#libkrunfw.}
        LIBKRUNFW_ABI=${LIBKRUNFW_ABI%.dylib}
    fi

    case "$LIBKRUNFW_ABI" in
        ''|*[!0-9]*) error "release bundle contains an invalid libkrunfw ABI version" ;;
    esac
}

link_command() {
    _name=$1
    _target=$2
    _link="$LOCAL_BIN_DIR/$_name"

    if [ -e "$_link" ] && [ ! -L "$_link" ]; then
        warn "Skipped $_link because it already exists and is not a symlink"
        return
    fi

    mkdir -p "$LOCAL_BIN_DIR"
    ln -sf "$_target" "$_link"
    success "Linked $_link -> $_target"
}

link_commands() {
    link_command msb "$BIN_DIR/msb"
    link_command microsandbox "$BIN_DIR/microsandbox"

    COMMAND_HINT="msb"
    case ":$PATH:" in
        *":$LOCAL_BIN_DIR:"*) ;;
        *)
            COMMAND_HINT="$LOCAL_BIN_DIR/msb"
            printf "\n"
            printf "  ${YELLOW}Note:${RESET} %s is not on your PATH.\n" "$LOCAL_BIN_DIR"
            printf "  Add it to your shell profile if you want to run ${BOLD}msb${RESET} directly:\n"
            printf "\n"
            printf "    ${DIM}export${RESET} PATH=\"%s:\$PATH\"\n" "$LOCAL_BIN_DIR"
            printf "\n"
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Progress bar
# ---------------------------------------------------------------------------

# Draw a progress bar: progress_bar <current> <total> <label>
progress_bar() {
    _current=$1
    _total=$2
    _label=$3

    if [ "$_total" -eq 0 ]; then
        return
    fi

    _percent=$(( _current * 100 / _total ))
    _filled=$(( _current * BAR_WIDTH / _total ))
    _empty=$(( BAR_WIDTH - _filled ))

    # Build filled and empty bar parts separately
    _filled_bar=""
    _i=0
    while [ "$_i" -lt "$_filled" ]; do
        _filled_bar="${_filled_bar}#"
        _i=$(( _i + 1 ))
    done
    _empty_bar=""
    _i=0
    while [ "$_i" -lt "$_empty" ]; do
        _empty_bar="${_empty_bar}-"
        _i=$(( _i + 1 ))
    done

    # Size in MB
    _current_mb=$(( _current / 1048576 ))
    _total_mb=$(( _total / 1048576 ))

    printf "\r${DIM}[${RESET}${GREEN}%s${RESET}${DIM}%s${RESET}${DIM}]${RESET} %3d%%  %dMB/%dMB  %s" \
        "$_filled_bar" "$_empty_bar" \
        "$_percent" "$_current_mb" "$_total_mb" "$_label"
}

# Download with custom progress bar: download <url> <dest>
download() {
    _url=$1
    _dest=$2
    _label=$(basename "$_dest")

    # Get file size via HEAD request
    _content_length=$(curl -fsSLI "$_url" 2>/dev/null | grep -i content-length | tail -1 | tr -d '[:space:]' | cut -d: -f2 || echo "0")

    if [ -z "$_content_length" ] || [ "$_content_length" = "0" ]; then
        # Fallback: download without progress
        info "Downloading $_label..."
        curl -fsSL "$_url" -o "$_dest" || error "Failed to download $_url"
        return
    fi

    # Download to a temp file in background
    _tmp="${_dest}.part"
    curl -fsSL "$_url" -o "$_tmp" 2>/dev/null &
    _pid=$!

    # Monitor progress
    while kill -0 "$_pid" 2>/dev/null; do
        if [ -f "$_tmp" ]; then
            _current=$(wc -c < "$_tmp" 2>/dev/null | tr -d '[:space:]' || echo "0")
            progress_bar "$_current" "$_content_length" "$_label"
        fi
        sleep 0.2 2>/dev/null || sleep 1
    done

    # Wait for curl to finish and check exit code
    if wait "$_pid"; then
        # Final progress bar at 100%
        progress_bar "$_content_length" "$_content_length" "$_label"
        printf "\n"
    else
        printf "\n"
        rm -f "$_tmp"
        error "Failed to download $_url"
    fi

    mv "$_tmp" "$_dest"
}

# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------

detect_platform() {
    _os=$(uname -s | tr '[:upper:]' '[:lower:]')
    _arch=$(uname -m)

    case "$_os" in
        linux)  OS="linux" ;;
        darwin) OS="darwin" ;;
        *)      error "Unsupported operating system: $_os" ;;
    esac

    case "$_arch" in
        x86_64|amd64)   ARCH="x86_64" ;;
        aarch64|arm64)  ARCH="aarch64" ;;
        *)              error "Unsupported architecture: $_arch" ;;
    esac

    # x86_64 macOS is not supported (libkrun HVF backend is aarch64-only)
    if [ "$OS" = "darwin" ] && [ "$ARCH" = "x86_64" ]; then
        error "x86_64 macOS is not supported. Microsandbox requires Apple Silicon (M1+)."
    fi

    TARGET="${OS}-${ARCH}"
}

parse_glibc_version() {
    _value=$1
    _version=$(printf '%s\n' "$_value" | sed -n 's/.* \([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p' | head -1)
    if [ -n "$_version" ]; then
        printf '%s\n' "$_version"
    fi
}

detect_glibc_version() {
    if command -v getconf > /dev/null 2>&1; then
        _glibc=$(getconf GNU_LIBC_VERSION 2>/dev/null || true)
        _version=$(parse_glibc_version "$_glibc")
        if [ -n "$_version" ]; then
            printf '%s\n' "$_version"
            return 0
        fi
    fi

    if command -v ldd > /dev/null 2>&1; then
        _ldd_version=$(ldd --version 2>&1 || true)
        case "$_ldd_version" in
            *musl*) return 1 ;;
        esac
        _version=$(parse_glibc_version "$_ldd_version")
        if [ -n "$_version" ]; then
            printf '%s\n' "$_version"
            return 0
        fi
    fi

    return 1
}

glibc_version_lt() {
    _lhs_major=$(printf '%s\n' "$1" | cut -d. -f1)
    _lhs_minor=$(printf '%s\n' "$1" | cut -d. -f2)
    _rhs_major=$(printf '%s\n' "$2" | cut -d. -f1)
    _rhs_minor=$(printf '%s\n' "$2" | cut -d. -f2)

    if [ "$_lhs_major" -lt "$_rhs_major" ]; then
        return 0
    fi
    if [ "$_lhs_major" -gt "$_rhs_major" ]; then
        return 1
    fi
    [ "$_lhs_minor" -lt "$_rhs_minor" ]
}

check_linux_compatibility() {
    _glibc_version=$(detect_glibc_version || true)
    _glibc_requirement="Microsandbox Linux releases require glibc ${LINUX_GLIBC_MIN_VERSION} or newer"

    if [ -z "$_glibc_version" ]; then
        error "${_glibc_requirement}, but a compatible glibc runtime was not detected. Please use a glibc-based Linux environment."
    fi

    if glibc_version_lt "$_glibc_version" "$LINUX_GLIBC_MIN_VERSION"; then
        error "${_glibc_requirement}, but this system has glibc ${_glibc_version}. Please use a newer glibc-based Linux environment."
    fi
}

# ---------------------------------------------------------------------------
# Version resolution
# ---------------------------------------------------------------------------

get_latest_version() {
    _url="https://api.github.com/repos/${GITHUB_REPO}/releases/latest"
    VERSION=$(curl -fsSL "$_url" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/')

    if [ -z "$VERSION" ]; then
        error "Could not determine latest release version"
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    need_cmd curl
    need_cmd tar
    need_cmd uname
    if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
        error "required command not found: sha256sum or shasum"
    fi

    printf "\n"
    printf "  ${BOLD}Microsandbox Installer${RESET}\n"
    printf "\n"

    detect_platform
    info "Detected platform: $TARGET"

    if [ "$OS" = "linux" ]; then
        check_linux_compatibility
    fi

    get_latest_version
    info "Latest version: $VERSION"

    _base_url="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}"
    _bundle="microsandbox-${TARGET}.tar.gz"
    _checksums="checksums.sha256"
    _tmp_dir=$(mktemp -d)
    trap 'rm -rf "$_tmp_dir"' EXIT

    # Download bundle and checksums
    info "Downloading microsandbox..."
    download "${_base_url}/${_bundle}" "${_tmp_dir}/${_bundle}"
    download "${_base_url}/${_checksums}" "${_tmp_dir}/${_checksums}"

    # Verify checksum
    info "Verifying checksum..."
    cd "$_tmp_dir"
    if command -v sha256sum > /dev/null 2>&1; then
        grep -F "$_bundle" "$_checksums" | sha256sum -c --quiet - || error "Checksum verification failed"
    else
        _expected=$(grep -F "$_bundle" "$_checksums" | awk '{print $1}')
        _actual=$(shasum -a 256 "$_bundle" | awk '{print $1}')
        if [ "$_expected" != "$_actual" ]; then
            error "Checksum verification failed"
        fi
    fi
    success "Checksum verified"

    # Extract
    info "Extracting..."
    tar -xzf "$_bundle"
    resolve_libkrunfw_artifact

    # Install binaries.
    # install(1) unlinks the target first, so the binary gets a fresh inode
    # even if a previous version is running.
    mkdir -p "$BIN_DIR"
    install -m 755 msb "$BIN_DIR/msb"

    # Also expose the binary as `microsandbox` so users can invoke it under
    # either name (matches the entry point shipped by the SDK packages).
    ln -sf msb "$BIN_DIR/microsandbox"

    # Install libkrunfw. Use install(1) on Linux (handles running binaries).
    # On macOS, cp+mv for a fresh inode — macOS caches code signatures on the
    # vnode, so overwriting a running library in-place can cause issues.
    mkdir -p "$LIB_DIR"
    if [ "$OS" = "linux" ]; then
        install -m 644 "$LIBKRUNFW_FILE" "$LIB_DIR/$LIBKRUNFW_FILE"
        ln -sf "$LIBKRUNFW_FILE" "$LIB_DIR/libkrunfw.so.${LIBKRUNFW_ABI}"
        ln -sf "libkrunfw.so.${LIBKRUNFW_ABI}" "$LIB_DIR/libkrunfw.so"
    elif [ "$OS" = "darwin" ]; then
        cp "$LIBKRUNFW_FILE" "$LIB_DIR/${LIBKRUNFW_FILE}.tmp" && mv "$LIB_DIR/${LIBKRUNFW_FILE}.tmp" "$LIB_DIR/$LIBKRUNFW_FILE"
        ln -sf "$LIBKRUNFW_FILE" "$LIB_DIR/libkrunfw.dylib"
    fi

    success "Installed msb to $BIN_DIR/msb"
    success "Linked microsandbox -> msb in $BIN_DIR/"
    success "Installed libkrunfw to $LIB_DIR/"

    link_commands

    success "Installation complete! Run '$COMMAND_HINT --help' to get started."
    printf "\n"
}

main "$@"
