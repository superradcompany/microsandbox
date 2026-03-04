# Build agentd as a static Linux/musl binary. Builds natively with the musl target.
# Requires: musl-tools (apt install musl-tools) or musl-dev (apk add musl-dev).
[linux]
build-agentd:
    @command -v musl-gcc >/dev/null || { echo "error: musl-gcc not found. Install your distro's musl toolchain."; exit 1; }
    rustup target add x86_64-unknown-linux-musl 2>/dev/null || true
    cargo build --release -p microsandbox-agentd --target x86_64-unknown-linux-musl
    mkdir -p build
    cp target/x86_64-unknown-linux-musl/release/microsandbox-agentd build/microsandbox-agentd

# Build agentd as a static Linux/musl binary. Cross-compiles via Docker.
# Requires: docker.
[macos]
build-agentd:
    #!/usr/bin/env bash
    set -euo pipefail
    command -v docker >/dev/null || { echo "error: docker not found. Install Docker Desktop."; exit 1; }
    docker build -f Dockerfile.agentd -t microsandbox-agentd-build .
    mkdir -p build
    id=$(docker create microsandbox-agentd-build /dev/null)
    docker cp "$id:/microsandbox-agentd" build/microsandbox-agentd
    docker rm "$id" > /dev/null

# Clean build artifacts.
clean:
    rm -rf build
