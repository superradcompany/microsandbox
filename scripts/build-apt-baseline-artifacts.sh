#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/apt-common.sh
source "$SCRIPT_DIR/lib/apt-common.sh"

usage() {
    cat <<'EOF'
Usage: scripts/build-apt-baseline-artifacts.sh --output-dir <dir> [--image <container-image>]

Build the Linux artifacts used for APT packaging on an older Debian baseline so
the resulting package remains compatible with the supported Debian/Ubuntu matrix.
EOF
}

OUTPUT_DIR=""
BASELINE_IMAGE="${APT_BASELINE_IMAGE:-docker.io/library/rust:1-bullseye}"
CONTAINER_RUNTIME="${CONTAINER_RUNTIME:-docker}"
LIBKRUNFW_VERSION="${LIBKRUNFW_VERSION:-5.2.1}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --image)
            BASELINE_IMAGE="$2"
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

[[ -n "$OUTPUT_DIR" ]] || {
    usage >&2
    exit 1
}

require_cmd "$CONTAINER_RUNTIME"

REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR_ABS="$(mkdir -p "$OUTPUT_DIR" && cd "$OUTPUT_DIR" && pwd)"
HOST_UID="$(id -u)"
HOST_GID="$(id -g)"

"$CONTAINER_RUNTIME" run --rm \
    -e DEBIAN_FRONTEND=noninteractive \
    -e HOST_UID="$HOST_UID" \
    -e HOST_GID="$HOST_GID" \
    -e LIBKRUNFW_VERSION="$LIBKRUNFW_VERSION" \
    -e OUTPUT_DIR_ABS="$OUTPUT_DIR_ABS" \
    -v "$REPO_ROOT":/workspace \
    -w /workspace \
    "$BASELINE_IMAGE" \
    bash -euo pipefail -c '
        export PATH=/usr/local/cargo/bin:$PATH

        apt-get update
        apt-get install -y \
            bc \
            ca-certificates \
            flex \
            bison \
            gcc \
            libcap-ng-dev \
            libdbus-1-dev \
            libelf-dev \
            make \
            musl-tools \
            pkg-config \
            python3-pyelftools

        build_root="$(mktemp -d)"
        trap '\''rm -rf "$build_root"'\'' EXIT

        export CARGO_TARGET_DIR="$build_root/target"

        case "$(uname -m)" in
            x86_64)
                agentd_target="x86_64-unknown-linux-musl"
                ;;
            aarch64)
                agentd_target="aarch64-unknown-linux-musl"
                ;;
            *)
                echo "error: unsupported architecture for agentd build: $(uname -m)" >&2
                exit 1
                ;;
        esac

        libkrunfw_root="$build_root/libkrunfw"
        cp -a /workspace/vendor/libkrunfw/. "$libkrunfw_root/"

        rustup target add "$agentd_target"
        mkdir -p /workspace/build
        cargo build --release --manifest-path crates/agentd/Cargo.toml --target "$agentd_target"
        install -m755 \
            "$CARGO_TARGET_DIR/$agentd_target/release/agentd" \
            /workspace/build/agentd

        cargo build --release --no-default-features --features net -p microsandbox-cli
        make -C "$libkrunfw_root" -j"$(nproc)"

        install -d "$OUTPUT_DIR_ABS"
        install -m755 "$CARGO_TARGET_DIR/release/msb" "$OUTPUT_DIR_ABS/msb"
        install -m644 \
            "$libkrunfw_root/libkrunfw.so.${LIBKRUNFW_VERSION}" \
            "$OUTPUT_DIR_ABS/libkrunfw.so.${LIBKRUNFW_VERSION}"

        chown -R "$HOST_UID:$HOST_GID" /workspace/build "$OUTPUT_DIR_ABS"
    '

printf '%s\n' "$OUTPUT_DIR_ABS"
