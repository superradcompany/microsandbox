# Version constants for libkrunfw. Keep in sync with microsandbox-utils/lib/lib.rs.
LIBKRUNFW_ABI := "5"
LIBKRUNFW_VERSION := "5.2.1"

# Build all binary dependencies (agentd + libkrunfw).
build-deps: build-agentd build-libkrunfw

# Build agentd as a static Linux/musl binary. Requires: musl-tools (apt) or musl-dev (apk).
[linux]
build-agentd:
    @command -v musl-gcc >/dev/null || { echo "error: musl-gcc not found. Install your distro's musl toolchain."; exit 1; }
    rustup target add x86_64-unknown-linux-musl 2>/dev/null || true
    cargo build --release -p microsandbox-agentd --target x86_64-unknown-linux-musl
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

# Build the msb CLI binary.
[linux]
build-msb mode="debug": build-agentd
    cargo build {{ if mode == "release" { "--release" } else { "" } }} --no-default-features -p microsandbox-cli
    mkdir -p build
    cp target/{{ mode }}/msb build/msb

# Build and sign the msb CLI binary.
[macos]
build-msb mode="debug": build-agentd
    cargo build {{ if mode == "release" { "--release" } else { "" } }} --no-default-features -p microsandbox-cli
    mkdir -p build
    cp target/{{ mode }}/msb build/msb
    codesign --entitlements msb-entitlements.plist --force -s - build/msb

# Build the msbnet binary.
[linux]
build-msbnet mode="debug":
    cargo build {{ if mode == "release" { "--release" } else { "" } }} -p microsandbox-network --bin msbnet
    mkdir -p build
    cp target/{{ mode }}/msbnet build/msbnet

# Build and sign the msbnet binary.
[macos]
build-msbnet mode="debug":
    cargo build {{ if mode == "release" { "--release" } else { "" } }} -p microsandbox-network --bin msbnet
    mkdir -p build
    cp target/{{ mode }}/msbnet build/msbnet
    codesign --entitlements msbnet-entitlements.plist --force -s - build/msbnet

# Build everything: agentd, libkrunfw, msb, and msbnet.
[linux]
build mode="debug": (build-msb mode) _ensure-libkrunfw (build-msbnet mode)

# Build everything: agentd, libkrunfw, msb, and msbnet.
[macos]
build mode="debug": (build-msb mode) _ensure-libkrunfw (build-msbnet mode)

# Install msb, msbnet, and libkrunfw to ~/.microsandbox/{bin,lib}/ and configure shell paths. Requires: just build.
[linux]
install:
    #!/usr/bin/env bash
    set -euo pipefail
    test -f build/msb || { echo "error: build/msb not found. Run 'just build' first."; exit 1; }
    test -f build/msbnet || { echo "error: build/msbnet not found. Run 'just build' first."; exit 1; }
    test -f build/libkrunfw.so.{{ LIBKRUNFW_VERSION }} || { echo "error: build/libkrunfw.so.{{ LIBKRUNFW_VERSION }} not found. Run 'just build-deps' first."; exit 1; }

    # Install msb and msbnet to ~/.microsandbox/bin/.
    mkdir -p ~/.microsandbox/bin
    install -m755 build/msb ~/.microsandbox/bin/msb
    install -m755 build/msbnet ~/.microsandbox/bin/msbnet
    echo "Installed msb → ~/.microsandbox/bin/msb"
    echo "Installed msbnet → ~/.microsandbox/bin/msbnet"

    # Install libkrunfw to ~/.microsandbox/lib/.
    mkdir -p ~/.microsandbox/lib
    cp build/libkrunfw.so.{{ LIBKRUNFW_VERSION }} ~/.microsandbox/lib/
    ln -sf libkrunfw.so.{{ LIBKRUNFW_VERSION }} ~/.microsandbox/lib/libkrunfw.so.{{ LIBKRUNFW_ABI }}
    ln -sf libkrunfw.so.{{ LIBKRUNFW_ABI }} ~/.microsandbox/lib/libkrunfw.so
    echo "Installed libkrunfw → ~/.microsandbox/lib/"

    echo ""
    echo "Remember to add ~/.microsandbox/bin to your PATH and ~/.microsandbox/lib to your LD_LIBRARY_PATH."

# Install msb, msbnet, and libkrunfw to ~/.microsandbox/{bin,lib}/. Requires: just build.
[macos]
install:
    #!/usr/bin/env bash
    set -euo pipefail
    test -f build/msb || { echo "error: build/msb not found. Run 'just build' first."; exit 1; }
    test -f build/msbnet || { echo "error: build/msbnet not found. Run 'just build' first."; exit 1; }
    test -f build/libkrunfw.{{ LIBKRUNFW_ABI }}.dylib || { echo "error: build/libkrunfw.{{ LIBKRUNFW_ABI }}.dylib not found. Run 'just build-deps' first."; exit 1; }

    # Install msb and msbnet to ~/.microsandbox/bin/ (cp preserves codesign; install strips it).
    mkdir -p ~/.microsandbox/bin
    cp build/msb ~/.microsandbox/bin/msb
    cp build/msbnet ~/.microsandbox/bin/msbnet
    echo "Installed msb → ~/.microsandbox/bin/msb"
    echo "Installed msbnet → ~/.microsandbox/bin/msbnet"

    # Install libkrunfw to ~/.microsandbox/lib/.
    mkdir -p ~/.microsandbox/lib
    cp build/libkrunfw.{{ LIBKRUNFW_ABI }}.dylib ~/.microsandbox/lib/
    ln -sf libkrunfw.{{ LIBKRUNFW_ABI }}.dylib ~/.microsandbox/lib/libkrunfw.dylib
    echo "Installed libkrunfw → ~/.microsandbox/lib/"

    echo ""
    echo "Remember to add ~/.microsandbox/bin to your PATH and ~/.microsandbox/lib to your DYLD_LIBRARY_PATH."

# Remove installed binaries from ~/.microsandbox/{bin,lib}/.
uninstall:
    #!/usr/bin/env bash
    set -euo pipefail
    rm -f ~/.microsandbox/bin/msb
    rm -f ~/.microsandbox/bin/msbnet
    rm -f ~/.microsandbox/lib/libkrunfw*
    echo "Removed msb, msbnet, and libkrunfw from ~/.microsandbox/"

# Clean build artifacts.
clean:
    rm -rf build
    cd vendor/libkrunfw && make clean || true
