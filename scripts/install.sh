#!/bin/sh
# Microsandbox installer
# Usage: curl -fsSL https://microsandbox.dev/install | sh
set -eu

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

GITHUB_REPO="zerocore-ai/microsandbox"
INSTALL_DIR="$HOME/.microsandbox"
BIN_DIR="$INSTALL_DIR/bin"
LIB_DIR="$INSTALL_DIR/lib"

# libkrunfw versioned filenames (must match the build)
LIBKRUNFW_VERSION="5.2.1"
LIBKRUNFW_ABI="5"

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

    printf "\r    ${DIM}[${RESET}${GREEN}%s${RESET}${DIM}%s${RESET}${DIM}]${RESET} %3d%%  %dMB/%dMB  %s" \
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

    # Install binaries
    mkdir -p "$BIN_DIR"
    install -m 755 msb "$BIN_DIR/msb"
    install -m 755 msbnet "$BIN_DIR/msbnet"

    # Install libkrunfw
    mkdir -p "$LIB_DIR"
    if [ "$OS" = "linux" ]; then
        cp "libkrunfw.so.${LIBKRUNFW_VERSION}" "$LIB_DIR/"
        ln -sf "libkrunfw.so.${LIBKRUNFW_VERSION}" "$LIB_DIR/libkrunfw.so.${LIBKRUNFW_ABI}"
        ln -sf "libkrunfw.so.${LIBKRUNFW_ABI}" "$LIB_DIR/libkrunfw.so"
    elif [ "$OS" = "darwin" ]; then
        cp "libkrunfw.${LIBKRUNFW_ABI}.dylib" "$LIB_DIR/"
        ln -sf "libkrunfw.${LIBKRUNFW_ABI}.dylib" "$LIB_DIR/libkrunfw.dylib"
    fi

    success "Installed msb to $BIN_DIR/msb"
    success "Installed msbnet to $BIN_DIR/msbnet"
    success "Installed libkrunfw to $LIB_DIR/"

    # Print setup instructions
    printf "\n"
    printf "  ${BOLD}Setup${RESET}\n"
    printf "\n"
    printf "  Add the following to your shell profile:\n"
    printf "\n"

    if [ "$OS" = "linux" ]; then
        printf "    ${DIM}export${RESET} PATH=\"%s:\$PATH\"\n" "$BIN_DIR"
        printf "    ${DIM}export${RESET} LD_LIBRARY_PATH=\"%s\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}\"\n" "$LIB_DIR"
    elif [ "$OS" = "darwin" ]; then
        printf "    ${DIM}export${RESET} PATH=\"%s:\$PATH\"\n" "$BIN_DIR"
        printf "    ${DIM}export${RESET} DYLD_LIBRARY_PATH=\"%s\${DYLD_LIBRARY_PATH:+:\$DYLD_LIBRARY_PATH}\"\n" "$LIB_DIR"
    fi

    printf "\n"
    printf "  Then restart your shell or run:\n"
    printf "\n"
    printf "    ${DIM}source ~/.bashrc  ${RESET}${DIM}# or ~/.zshrc${RESET}\n"
    printf "\n"
    success "Installation complete! Run 'msb --help' to get started."
    printf "\n"
}

main "$@"
