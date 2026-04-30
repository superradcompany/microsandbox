#!/bin/sh
# Microsandbox installer
# Usage: curl -fsSL https://install.microsandbox.dev | sh
set -eu

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

GITHUB_REPO="superradcompany/microsandbox"
INSTALL_DIR="$HOME/.microsandbox"
BIN_DIR="$INSTALL_DIR/bin"
LIB_DIR="$INSTALL_DIR/lib"

# libkrunfw versioned filenames (must match the build)
LIBKRUNFW_VERSION="5.2.1"
LIBKRUNFW_ABI="5"

# Current Linux release bundles are built on GitHub Actions ubuntu-latest,
# which currently maps to Ubuntu 24.04 (glibc 2.39).
LINUX_GLIBC_MIN_VERSION="2.39"

# Shell config markers
MARKER_START="# >>> microsandbox >>>"
MARKER_END="# <<< microsandbox <<<"

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
# Shell configuration
# ---------------------------------------------------------------------------

detect_current_shell() {
    _shell_path="${SHELL:-/bin/sh}"
    case "$(basename "$_shell_path")" in
        bash) CURRENT_SHELL="bash" ;;
        zsh)  CURRENT_SHELL="zsh" ;;
        fish) CURRENT_SHELL="fish" ;;
        *)    CURRENT_SHELL="sh" ;;
    esac
}

# Update a shell config file idempotently with a marker block.
# If the file doesn't exist it is created. If a marker block already
# exists it is replaced in-place. Otherwise the block is appended.
update_shell_config() {
    _file=$1
    _block=$2

    if [ ! -f "$_file" ]; then
        mkdir -p "$(dirname "$_file")"
        printf '%s\n' "$_block" > "$_file"
        return 0
    fi

    # Back up the original file on first modification
    if [ ! -f "${_file}.pre-microsandbox" ]; then
        cp -p "$_file" "${_file}.pre-microsandbox"
    fi

    if grep -qF "$MARKER_START" "$_file"; then
        # Replace existing block in-place (ENVIRON avoids awk -v escape issues)
        _tmp="${_file}.msb_tmp"
        _MSB_BLOCK="$_block" awk '
            BEGIN { block = ENVIRON["_MSB_BLOCK"] }
            /^# >>> microsandbox >>>/ {
                if (!done) { print block; done=1 }
                skip=1; next
            }
            /^# <<< microsandbox <<</ { skip=0; next }
            !skip
        ' "$_file" > "$_tmp"
        mv "$_tmp" "$_file"
    else
        # Append with a leading blank line
        printf '\n%s\n' "$_block" >> "$_file"
    fi
}

# Configure all relevant shell config files with PATH and library path.
configure_shell() {
    detect_current_shell

    # Build POSIX block (sh, bash, zsh)
    if [ "$OS" = "linux" ]; then
        _lib_line='export LD_LIBRARY_PATH="$HOME/.microsandbox/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"'
    else
        _lib_line='export DYLD_LIBRARY_PATH="$HOME/.microsandbox/lib${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"'
    fi
    _path_line='export PATH="$HOME/.microsandbox/bin:$PATH"'
    _posix_block="${MARKER_START}
${_path_line}
${_lib_line}
${MARKER_END}"

    # Build fish block
    if [ "$OS" = "linux" ]; then
        _fish_lib='set -gx LD_LIBRARY_PATH "$HOME/.microsandbox/lib" $LD_LIBRARY_PATH'
    else
        _fish_lib='set -gx DYLD_LIBRARY_PATH "$HOME/.microsandbox/lib" $DYLD_LIBRARY_PATH'
    fi
    _fish_path='set -gx PATH "$HOME/.microsandbox/bin" $PATH'
    _fish_block="${MARKER_START}
${_fish_path}
${_fish_lib}
${MARKER_END}"

    _did_bashrc=false
    _did_zshrc=false
    _did_profile=false

    printf "\n"
    printf "  ${BOLD}Shell Configuration${RESET}\n"
    printf "\n"

    # Update existing POSIX shell config files
    for _file in "$HOME/.profile" "$HOME/.bash_profile" "$HOME/.bashrc" "$HOME/.zshrc"; do
        if [ -f "$_file" ]; then
            update_shell_config "$_file" "$_posix_block"
            _display="${_file#$HOME}"
            success "Configured ~${_display}"
            case "$_file" in
                */.bashrc)  _did_bashrc=true ;;
                */.zshrc)   _did_zshrc=true ;;
                */.profile) _did_profile=true ;;
            esac
        fi
    done

    # If current shell's primary config wasn't updated, create it
    case "$CURRENT_SHELL" in
        bash)
            if [ "$_did_bashrc" = false ]; then
                update_shell_config "$HOME/.bashrc" "$_posix_block"
                success "Configured ~/.bashrc"
            fi
            ;;
        zsh)
            if [ "$_did_zshrc" = false ]; then
                update_shell_config "$HOME/.zshrc" "$_posix_block"
                success "Configured ~/.zshrc"
            fi
            ;;
        sh)
            if [ "$_did_profile" = false ]; then
                update_shell_config "$HOME/.profile" "$_posix_block"
                success "Configured ~/.profile"
            fi
            ;;
    esac

    # Fish: update if config dir exists or fish is the current shell
    if [ -d "$HOME/.config/fish" ] || [ "$CURRENT_SHELL" = "fish" ]; then
        _fish_conf="$HOME/.config/fish/conf.d/microsandbox.fish"
        update_shell_config "$_fish_conf" "$_fish_block"
        success "Configured ~/.config/fish/conf.d/microsandbox.fish"
    fi

    printf "\n"
    printf "  Restart your shell or run:\n"
    printf "\n"
    case "$CURRENT_SHELL" in
        fish) printf "    ${DIM}source ~/.config/fish/conf.d/microsandbox.fish${RESET}\n" ;;
        zsh)  printf "    ${DIM}source ~/.zshrc${RESET}\n" ;;
        bash) printf "    ${DIM}source ~/.bashrc${RESET}\n" ;;
        *)    printf "    ${DIM}. ~/.profile${RESET}\n" ;;
    esac
    printf "\n"
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
    # Parse arguments
    MODIFY_PATH="yes"
    for _arg in "$@"; do
        case "$_arg" in
            --no-modify-path) MODIFY_PATH="no" ;;
        esac
    done

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
        install -m 644 "libkrunfw.so.${LIBKRUNFW_VERSION}" "$LIB_DIR/libkrunfw.so.${LIBKRUNFW_VERSION}"
        ln -sf "libkrunfw.so.${LIBKRUNFW_VERSION}" "$LIB_DIR/libkrunfw.so.${LIBKRUNFW_ABI}"
        ln -sf "libkrunfw.so.${LIBKRUNFW_ABI}" "$LIB_DIR/libkrunfw.so"
    elif [ "$OS" = "darwin" ]; then
        cp "libkrunfw.${LIBKRUNFW_ABI}.dylib" "$LIB_DIR/libkrunfw.${LIBKRUNFW_ABI}.dylib.tmp" && mv "$LIB_DIR/libkrunfw.${LIBKRUNFW_ABI}.dylib.tmp" "$LIB_DIR/libkrunfw.${LIBKRUNFW_ABI}.dylib"
        ln -sf "libkrunfw.${LIBKRUNFW_ABI}.dylib" "$LIB_DIR/libkrunfw.dylib"
    fi

    success "Installed msb to $BIN_DIR/msb"
    success "Linked microsandbox -> msb in $BIN_DIR/"
    success "Installed libkrunfw to $LIB_DIR/"

    # Configure shell environment
    if [ "$MODIFY_PATH" = "yes" ]; then
        configure_shell
    else
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
    fi

    success "Installation complete! Run 'msb --tree' to get started."
    printf "\n"
}

main "$@"
