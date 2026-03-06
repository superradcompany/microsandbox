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

# Build the msb CLI binary (release mode).
build: build-deps
    cargo build --release -p microsandbox-cli
    mkdir -p build
    cp target/release/msb build/msb

# Build and sign msb for macOS (hypervisor entitlement required for HVF).
[macos]
build-signed: build
    codesign --entitlements entitlements.plist --force -s - build/msb

# Clean build artifacts.
clean:
    rm -rf build
    cd vendor/libkrunfw && make clean || true
