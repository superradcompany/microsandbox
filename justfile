# Version constants for libkrunfw. Keep in sync with microsandbox-utils/lib/lib.rs.
LIBKRUNFW_ABI := "5"
LIBKRUNFW_VERSION := "5.2.1"
DEFAULT_PACKAGE_FORMAT := "deb"
LOCAL_PACKAGE_DIST_DIR := "dist/packages"
LINUX_PACKAGE_NAME := "microsandbox"

# Set up the development environment, build, and install. Prerequisites: just, git (+ Docker on macOS).
setup: _install-dev-deps
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

[linux]
_install-dev-deps:
    #!/usr/bin/env bash
    set -euo pipefail

    echo "==> Installing system dependencies..."
    sudo apt install build-essential musl-tools flex bison libelf-dev \
        python3-pyelftools pkg-config libdbus-1-dev libcap-ng-dev pre-commit

    echo "==> Checking Rust toolchain..."
    if ! command -v rustup &>/dev/null; then
        echo "    Rust not found. Installing via rustup..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
        source "$HOME/.cargo/env"
    fi

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

# Check for libkrunfw and build it only if not found in build/, ~/.microsandbox/lib/, or system paths.
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
    # Check system library paths via ldconfig.
    if ldconfig -p 2>/dev/null | grep -q libkrunfw; then
        echo "Found libkrunfw in system library paths"
        exit 0
    fi
    echo "libkrunfw not found — building from source..."
    just build-libkrunfw

# Check for libkrunfw and build it only if not found in build/, ~/.microsandbox/lib/, or system paths.
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

# Build libkrunfw on Linux. Requires: kernel build dependencies (gcc, make, flex, bison, etc.).
[linux]
_require-libkrunfw-build-tools:
    #!/usr/bin/env bash
    set -euo pipefail
    missing=()

    for cmd in bc bison flex gcc make python3; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing+=("$cmd")
        fi
    done

    if [ "${#missing[@]}" -gt 0 ]; then
        echo "error: missing build tools for libkrunfw: ${missing[*]}" >&2
        echo "hint: install them with: sudo apt-get install -y bc bison flex gcc make libelf-dev python3-pyelftools libcap-ng-dev" >&2
        exit 1
    fi

[linux]
build-libkrunfw: _require-libkrunfw-build-tools
    #!/usr/bin/env bash
    set -euo pipefail
    kernel_version="$(sed -n 's/^KERNEL_VERSION = //p' vendor/libkrunfw/Makefile | head -n1)"
    kernel_tarball="vendor/libkrunfw/tarballs/${kernel_version}.tar.xz"

    if [ -f "$kernel_tarball" ] && ! tar -tf "$kernel_tarball" >/dev/null 2>&1; then
        echo "Removing corrupt kernel tarball: $kernel_tarball"
        rm -f "$kernel_tarball"
    fi

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

# Build the msb CLI binary.
[linux]
build-msb mode="debug": build-agentd
    cargo build {{ if mode == "release" { "--release" } else { "" } }} --no-default-features --features net -p microsandbox-cli
    mkdir -p build
    cp target/{{ mode }}/msb build/msb

# Build and sign the msb CLI binary.
[macos]
build-msb mode="debug": build-agentd
    cargo build {{ if mode == "release" { "--release" } else { "" } }} --no-default-features --features net -p microsandbox-cli
    mkdir -p build
    cp target/{{ mode }}/msb build/msb
    codesign --entitlements msb-entitlements.plist --force -s - build/msb

# Build everything: agentd, libkrunfw, and msb.
[linux]
build mode="debug": (build-msb mode) _ensure-libkrunfw

# Build everything: agentd, libkrunfw, and msb.
[macos]
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
    echo "Remember to add ~/.microsandbox/bin to your PATH and ~/.microsandbox/lib to your LD_LIBRARY_PATH."

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
    echo "Remember to add ~/.microsandbox/bin to your PATH and ~/.microsandbox/lib to your DYLD_LIBRARY_PATH."

# Remove installed binaries from ~/.microsandbox/{bin,lib}/.
uninstall:
    #!/usr/bin/env bash
    set -euo pipefail
    rm -f ~/.microsandbox/bin/msb
    rm -f ~/.microsandbox/lib/libkrunfw*
    echo "Removed msb and libkrunfw from ~/.microsandbox/"

# Build a local Linux package from the current build outputs.
[linux]
package-local format=DEFAULT_PACKAGE_FORMAT revision="1": (build-msb "release") build-libkrunfw
    #!/usr/bin/env bash
    set -euo pipefail

    arch="$(uname -m)"
    package_format="{{ format }}"
    revision="{{ revision }}"
    version="$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n1)"
    output_dir="{{ LOCAL_PACKAGE_DIST_DIR }}/$package_format"

    test -n "$version" || { echo "error: could not determine workspace version from Cargo.toml"; exit 1; }

    case "$package_format" in
        deb)
            echo "==> Packaging {{ LINUX_PACKAGE_NAME }} $version-$revision as $package_format..."
            bash scripts/package-deb.sh \
                --arch "$arch" \
                --version "$version" \
                --revision "$revision" \
                --msb "build/msb" \
                --libkrunfw "build/libkrunfw.so.{{ LIBKRUNFW_VERSION }}" \
                --output-dir "$output_dir"
            ;;
        *)
            echo "error: unsupported local package format: $package_format" >&2
            echo "supported formats: deb" >&2
            exit 1
            ;;
    esac

# Build the local Linux package and install it with the matching system tool.
[linux]
install-package-local format=DEFAULT_PACKAGE_FORMAT revision="1": (package-local format revision)
    #!/usr/bin/env bash
    set -euo pipefail

    package_format="{{ format }}"
    revision="{{ revision }}"
    version="$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n1)"
    test -n "$version" || { echo "error: could not determine workspace version from Cargo.toml"; exit 1; }

    case "$package_format" in
        deb)
            case "$(uname -m)" in
                x86_64)
                    package_arch="amd64"
                    ;;
                aarch64)
                    package_arch="arm64"
                    ;;
                *)
                    echo "error: unsupported Debian architecture: $(uname -m)" >&2
                    exit 1
                    ;;
            esac
            package_path="$PWD/{{ LOCAL_PACKAGE_DIST_DIR }}/$package_format/{{ LINUX_PACKAGE_NAME }}_${version}-${revision}_${package_arch}.deb"
            ;;
        *)
            echo "error: unsupported local package format: $package_format" >&2
            echo "supported formats: deb" >&2
            exit 1
            ;;
    esac

    test -f "$package_path" || { echo "error: package not found: $package_path"; exit 1; }
    stage_dir="$(mktemp -d /tmp/microsandbox-package.XXXXXX)"
    stage_package="$stage_dir/$(basename "$package_path")"
    trap 'rm -rf "$stage_dir"' EXIT

    chmod 755 "$stage_dir"
    install -m644 "$package_path" "$stage_package"

    case "$package_format" in
        deb)
            echo "==> Installing $stage_package..."
            sudo apt-get update
            sudo apt install --reinstall -y "$stage_package"
            ;;
    esac

# Remove the locally installed Linux package with the matching system tool.
[linux]
uninstall-package-local format=DEFAULT_PACKAGE_FORMAT:
    #!/usr/bin/env bash
    set -euo pipefail

    package_format="{{ format }}"

    case "$package_format" in
        deb)
            if dpkg-query -W -f='${Status}' "{{ LINUX_PACKAGE_NAME }}" 2>/dev/null | grep -q "install ok installed"; then
                echo "==> Removing {{ LINUX_PACKAGE_NAME }}..."
                sudo apt remove -y "{{ LINUX_PACKAGE_NAME }}"
            else
                echo "{{ LINUX_PACKAGE_NAME }} is not installed."
            fi
            ;;
        *)
            echo "error: unsupported local package format: $package_format" >&2
            echo "supported formats: deb" >&2
            exit 1
            ;;
    esac

# Clean build artifacts.
clean:
    rm -rf build
    cd vendor/libkrunfw && make clean || true

# Run the filesystem benchmark harness with the default image and settings.
bench-fs:
    cd benchmarks && uv run bench_fs.py
