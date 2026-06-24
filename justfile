# Version constants for libkrunfw. Keep in sync with microsandbox-utils/lib/lib.rs.
LIBKRUNFW_ABI := "5"
LIBKRUNFW_VERSION := "5.2.1"

# Run Windows recipes through cmd so contributors do not need sh/Git Bash/MSYS in PATH.
set windows-shell := ["cmd.exe", "/c"]

# Set up the development environment, build, and install. Prerequisites: just, git, and platform toolchains.
[linux]
setup: _setup-unix

# Set up the development environment, build, and install. Prerequisites: just, git, and platform toolchains.
[macos]
setup: _setup-unix

# Set up the development environment, build, and install. Prerequisites: just, git, and platform toolchains.
[windows]
setup:
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/dev-windows.ps1 setup

# Shared Unix setup flow used by Linux and macOS.
_setup-unix: _install-dev-deps
    #!/usr/bin/env bash
    set -euo pipefail

    echo "==> Initializing submodules..."
    git submodule update --init --recursive

    echo "==> Building dependencies..."
    just build-deps

    echo "==> Building microsandbox..."
    just build

    echo "==> Installing..."
    just install

    echo "==> Setting up pre-commit hooks..."
    command -v pre-commit &>/dev/null || { echo "error: pre-commit not found."; exit 1; }
    pre-commit install

    echo ""
    echo "Setup complete!"

# Install Linux development prerequisites.
[linux]
_install-dev-deps:
    #!/usr/bin/env bash
    set -euo pipefail

    echo "==> Installing system dependencies..."
    sudo apt install build-essential musl-tools flex bison libelf-dev \
        python3-pyelftools pkg-config libcap-ng-dev pre-commit

    echo "==> Checking Rust toolchain..."
    if ! command -v rustup &>/dev/null; then
        echo "    Rust not found. Installing via rustup..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
        source "$HOME/.cargo/env"
    fi

# Install macOS development prerequisites.
[macos]
_install-dev-deps:
    #!/usr/bin/env bash
    set -euo pipefail

    echo "==> Checking prerequisites..."
    command -v docker &>/dev/null || { echo "error: Docker is required on macOS. Install Docker Desktop."; exit 1; }
    xcode-select -p &>/dev/null || { echo "==> Installing Xcode Command Line Tools..."; xcode-select --install; }

    echo "==> Checking Rust toolchain..."
    if ! command -v rustup &>/dev/null; then
        echo "    Rust not found. Installing via rustup..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
        source "$HOME/.cargo/env"
    fi

# Check Windows development prerequisites.
[windows]
_install-dev-deps:
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/dev-windows.ps1 install-dev-deps

# Build all binary dependencies (agentd + libkrunfw).
build-deps: build-agentd build-libkrunfw

# Build agentd as a static Linux/musl binary. Requires: musl-tools (apt) or musl-dev (apk).
[linux]
build-agentd:
    @command -v musl-gcc >/dev/null || { echo "error: musl-gcc not found. Install your distro's musl toolchain."; exit 1; }
    rustup target add x86_64-unknown-linux-musl 2>/dev/null || true
    cargo build --release --manifest-path crates/agentd/Cargo.toml --target-dir target --target x86_64-unknown-linux-musl
    mkdir -p build
    cp target/x86_64-unknown-linux-musl/release/agentd build/agentd
    touch build/agentd

# Build agentd as a static Linux/musl binary via Docker cross-compilation. Requires: docker.
[macos]
build-agentd:
    #!/usr/bin/env bash
    set -euo pipefail
    command -v docker >/dev/null || { echo "error: docker not found. Install Docker Desktop."; exit 1; }
    docker build -f Dockerfile.agentd -t microsandbox-agentd-build .
    mkdir -p build
    id=$(docker create microsandbox-agentd-build /dev/null)
    trap 'docker rm "$id" >/dev/null 2>&1' EXIT
    docker cp "$id:/agentd" build/agentd
    touch build/agentd

# Build agentd as a static Linux/musl binary via Docker Linux containers or WSL.
[windows]
build-agentd:
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/dev-windows.ps1 build-agentd

# Check for libkrunfw and build it only if not found in build/ or ~/.microsandbox/lib/.
[linux]
_ensure-libkrunfw:
    #!/usr/bin/env bash
    set -euo pipefail
    # Check build/ directory.
    if [ -f build/libkrunfw.so.{{ LIBKRUNFW_VERSION }} ]; then
        echo "Found libkrunfw in build/"
        exit 0
    fi
    # Check ~/.microsandbox/lib/.
    if [ -f ~/.microsandbox/lib/libkrunfw.so.{{ LIBKRUNFW_VERSION }} ]; then
        echo "Found libkrunfw in ~/.microsandbox/lib/"
        exit 0
    fi
    echo "libkrunfw not found — building from source..."
    just build-libkrunfw

# Check for libkrunfw and build it only if not found in build/ or ~/.microsandbox/lib/.
[macos]
_ensure-libkrunfw:
    #!/usr/bin/env bash
    set -euo pipefail
    # Check build/ directory.
    if [ -f build/libkrunfw.{{ LIBKRUNFW_ABI }}.dylib ]; then
        echo "Found libkrunfw in build/"
        exit 0
    fi
    # Check ~/.microsandbox/lib/.
    if [ -f ~/.microsandbox/lib/libkrunfw.{{ LIBKRUNFW_ABI }}.dylib ]; then
        echo "Found libkrunfw in ~/.microsandbox/lib/"
        exit 0
    fi
    echo "libkrunfw not found — building from source..."
    just build-libkrunfw

# Check for libkrunfw.dll and build it only if not found in build/ or ~/.microsandbox/lib/.
[windows]
_ensure-libkrunfw:
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/dev-windows.ps1 ensure-libkrunfw

# Build libkrunfw on Linux. Requires: kernel build dependencies (gcc, make, flex, bison, etc.).
[linux]
build-libkrunfw:
    #!/usr/bin/env bash
    set -euo pipefail
    cd vendor/libkrunfw
    make -j$(nproc)
    cd ../..
    mkdir -p build
    cp vendor/libkrunfw/libkrunfw.so.{{ LIBKRUNFW_VERSION }} build/
    cd build
    ln -sf libkrunfw.so.{{ LIBKRUNFW_VERSION }} libkrunfw.so.{{ LIBKRUNFW_ABI }}
    ln -sf libkrunfw.so.{{ LIBKRUNFW_ABI }} libkrunfw.so

# Build libkrunfw on macOS via Docker kernel build + host linking. Requires: docker, cc (Xcode CLT).
[macos]
build-libkrunfw:
    #!/usr/bin/env bash
    set -euo pipefail
    cd vendor/libkrunfw
    ./build_in_docker.sh
    cc -fPIC -DABI_VERSION={{ LIBKRUNFW_ABI }} -shared -o libkrunfw.{{ LIBKRUNFW_ABI }}.dylib kernel.c
    cd ../..
    mkdir -p build
    cp vendor/libkrunfw/libkrunfw.{{ LIBKRUNFW_ABI }}.dylib build/
    cd build
    ln -sf libkrunfw.{{ LIBKRUNFW_ABI }}.dylib libkrunfw.dylib

# Build libkrunfw on Windows via Docker/WSL kernel bundle build + host MSVC linking.
[windows]
build-libkrunfw:
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/dev-windows.ps1 build-libkrunfw

# Build the msb CLI binary.
[linux]
build-msb mode="debug": build-agentd
    cargo build {{ if mode == "release" { "--release" } else { "" } }} --no-default-features --features net,ssh -p microsandbox-cli
    mkdir -p build
    cp target/{{ mode }}/msb build/msb

# Build and sign the msb CLI binary.
[macos]
build-msb mode="debug": build-agentd
    cargo build {{ if mode == "release" { "--release" } else { "" } }} --no-default-features --features net,ssh -p microsandbox-cli
    mkdir -p build
    cp target/{{ mode }}/msb build/msb
    codesign --entitlements msb-entitlements.plist --force -s - build/msb

# Build the msb CLI binary for the native Windows MSVC target.
[windows]
build-msb mode="debug": build-agentd
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/dev-windows.ps1 build-msb {{ mode }}

# Build everything: agentd, libkrunfw, and msb.
[linux]
build mode="debug": (build-msb mode) _ensure-libkrunfw

# Build everything: agentd, libkrunfw, and msb.
[macos]
build mode="debug": (build-msb mode) _ensure-libkrunfw

# Build everything: agentd, libkrunfw, and msb.
[windows]
build mode="debug": (build-msb mode) _ensure-libkrunfw

# Install msb and libkrunfw to ~/.microsandbox/{bin,lib}/ and configure shell paths. Requires: just build.
[linux]
install:
    #!/usr/bin/env bash
    set -euo pipefail
    test -f build/msb || { echo "error: build/msb not found. Run 'just build' first."; exit 1; }
    test -f build/libkrunfw.so.{{ LIBKRUNFW_VERSION }} || { echo "error: build/libkrunfw.so.{{ LIBKRUNFW_VERSION }} not found. Run 'just build-deps' first."; exit 1; }

    # Install msb to ~/.microsandbox/bin/.
    mkdir -p ~/.microsandbox/bin
    install -m755 build/msb ~/.microsandbox/bin/msb
    echo "Installed msb → ~/.microsandbox/bin/msb"

    # Install libkrunfw to ~/.microsandbox/lib/.
    mkdir -p ~/.microsandbox/lib
    install -m644 build/libkrunfw.so.{{ LIBKRUNFW_VERSION }} ~/.microsandbox/lib/libkrunfw.so.{{ LIBKRUNFW_VERSION }}
    ln -sf libkrunfw.so.{{ LIBKRUNFW_VERSION }} ~/.microsandbox/lib/libkrunfw.so.{{ LIBKRUNFW_ABI }}
    ln -sf libkrunfw.so.{{ LIBKRUNFW_ABI }} ~/.microsandbox/lib/libkrunfw.so
    echo "Installed libkrunfw → ~/.microsandbox/lib/"

    echo ""
    echo "Remember to add ~/.microsandbox/bin to your PATH."

# Install msb and libkrunfw to ~/.microsandbox/{bin,lib}/. Requires: just build.
[macos]
install:
    #!/usr/bin/env bash
    set -euo pipefail
    test -f build/msb || { echo "error: build/msb not found. Run 'just build' first."; exit 1; }
    test -f build/libkrunfw.{{ LIBKRUNFW_ABI }}.dylib || { echo "error: build/libkrunfw.{{ LIBKRUNFW_ABI }}.dylib not found. Run 'just build-deps' first."; exit 1; }

    # Install msb to ~/.microsandbox/bin/.
    # Atomic mv to a fresh inode — macOS caches code signatures on the vnode,
    # so cp over a running binary can block new executions.
    mkdir -p ~/.microsandbox/bin
    install -m755 build/msb ~/.microsandbox/bin/msb.tmp && mv ~/.microsandbox/bin/msb.tmp ~/.microsandbox/bin/msb
    echo "Installed msb → ~/.microsandbox/bin/msb"

    # Install libkrunfw to ~/.microsandbox/lib/.
    # Atomic install to avoid corrupting a running VM's mmap'd library.
    mkdir -p ~/.microsandbox/lib
    cp build/libkrunfw.{{ LIBKRUNFW_ABI }}.dylib ~/.microsandbox/lib/libkrunfw.{{ LIBKRUNFW_ABI }}.dylib.tmp && mv ~/.microsandbox/lib/libkrunfw.{{ LIBKRUNFW_ABI }}.dylib.tmp ~/.microsandbox/lib/libkrunfw.{{ LIBKRUNFW_ABI }}.dylib
    ln -sf libkrunfw.{{ LIBKRUNFW_ABI }}.dylib ~/.microsandbox/lib/libkrunfw.dylib
    echo "Installed libkrunfw → ~/.microsandbox/lib/"

    echo ""
    echo "Remember to add ~/.microsandbox/bin to your PATH."

# Install msb and libkrunfw.dll to %USERPROFILE%\.microsandbox\{bin,lib}\ and configure user PATH.
[windows]
install:
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/dev-windows.ps1 install

# Remove installed binaries from ~/.microsandbox/{bin,lib}/.
[linux]
uninstall: _uninstall-unix

# Remove installed binaries from ~/.microsandbox/{bin,lib}/.
[macos]
uninstall: _uninstall-unix

# Shared Unix uninstall flow used by Linux and macOS.
_uninstall-unix:
    #!/usr/bin/env bash
    set -euo pipefail
    rm -f ~/.microsandbox/bin/msb
    rm -f ~/.microsandbox/lib/libkrunfw*
    echo "Removed msb and libkrunfw from ~/.microsandbox/"

# Remove installed binaries from %USERPROFILE%\.microsandbox\{bin,lib}\.
[windows]
uninstall:
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/dev-windows.ps1 uninstall

# Clean build artifacts.
[linux]
clean: _clean-unix

# Clean build artifacts.
[macos]
clean: _clean-unix

# Shared Unix clean flow used by Linux and macOS.
_clean-unix:
    rm -rf build
    cd vendor/libkrunfw && make clean || true

# Clean Windows build artifacts.
[windows]
clean:
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/dev-windows.ps1 clean
