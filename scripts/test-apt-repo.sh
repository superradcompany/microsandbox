#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: scripts/test-apt-repo.sh --repo-v1 <dir> --repo-v2 <dir> --keyring <path> \
  --bad-keyring <path> [--image <container> ...]

Validate install, reinstall, upgrade, remove, purge, and signature failures
against a local signed APT repository inside Debian/Ubuntu containers.
EOF
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "error: required command not found: $1" >&2
        exit 1
    }
}

canonical_path() {
    realpath "$1"
}

REPO_V1=""
REPO_V2=""
KEYRING=""
BAD_KEYRING=""
IMAGES=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --repo-v1)
            REPO_V1="$2"
            shift 2
            ;;
        --repo-v2)
            REPO_V2="$2"
            shift 2
            ;;
        --keyring)
            KEYRING="$2"
            shift 2
            ;;
        --bad-keyring)
            BAD_KEYRING="$2"
            shift 2
            ;;
        --image)
            IMAGES+=("$2")
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

[[ -n "$REPO_V1" && -n "$REPO_V2" && -n "$KEYRING" && -n "$BAD_KEYRING" ]] || {
    usage >&2
    exit 1
}

if [[ ${#IMAGES[@]} -eq 0 ]]; then
    IMAGES=("debian:12" "ubuntu:22.04" "ubuntu:24.04")
fi

require_cmd docker
require_cmd dpkg-deb
require_cmd realpath

[[ -d "$REPO_V1" && -d "$REPO_V2" ]] || {
    echo "error: repository directories must exist" >&2
    exit 1
}
[[ -f "$KEYRING" && -f "$BAD_KEYRING" ]] || {
    echo "error: keyring files must exist" >&2
    exit 1
}

REPO_V1="$(canonical_path "$REPO_V1")"
REPO_V2="$(canonical_path "$REPO_V2")"
KEYRING="$(canonical_path "$KEYRING")"
BAD_KEYRING="$(canonical_path "$BAD_KEYRING")"

DEB_V1="$(find "$REPO_V1/pool" -type f -name 'microsandbox_*.deb' | sort | head -n1)"
DEB_V2="$(find "$REPO_V2/pool" -type f -name 'microsandbox_*.deb' | sort | head -n1)"
VERSION_V1="$(dpkg-deb -f "$DEB_V1" Version)"
VERSION_V2="$(dpkg-deb -f "$DEB_V2" Version)"

for image in "${IMAGES[@]}"; do
    echo "==> Testing install and upgrade in $image"
    docker run --rm \
        -e DEBIAN_FRONTEND=noninteractive \
        -e VERSION_V1="$VERSION_V1" \
        -e VERSION_V2="$VERSION_V2" \
        -v "$REPO_V1":/repo-v1:ro \
        -v "$REPO_V2":/repo-v2:ro \
        -v "$KEYRING":/tmp/microsandbox-archive-keyring.gpg:ro \
        "$image" \
        bash -euxo pipefail -c '
            apt-get update
            apt-get install -y ca-certificates
            mkdir -p /root/.microsandbox
            touch /root/.microsandbox/state-marker

            install -Dm644 /tmp/microsandbox-archive-keyring.gpg \
                /usr/share/keyrings/microsandbox-archive-keyring.gpg
            echo "deb [signed-by=/usr/share/keyrings/microsandbox-archive-keyring.gpg] file:///repo-v1 stable main" \
                >/etc/apt/sources.list.d/microsandbox.list

            apt-get update
            apt-get install -y microsandbox
            test -x /usr/bin/msb
            versioned_lib="$(find /usr/lib/microsandbox -maxdepth 1 -type f -name "libkrunfw.so.*" | sort | head -n1)"
            test -n "$versioned_lib"
            soname_link="$(basename "$versioned_lib" | sed -E "s/^(libkrunfw\\.so\\.[0-9]+)\\..*$/\\1/")"
            test -L "/usr/lib/microsandbox/$soname_link"
            test -L /usr/lib/microsandbox/libkrunfw.so
            test "$(readlink "/usr/lib/microsandbox/$soname_link")" = "$(basename "$versioned_lib")"
            test "$(readlink /usr/lib/microsandbox/libkrunfw.so)" = "$soname_link"
            msb --version
            test "$(dpkg-query -W -f="\${Version}\n" microsandbox)" = "$VERSION_V1"

            apt-get install -y --reinstall microsandbox
            test "$(dpkg-query -W -f="\${Version}\n" microsandbox)" = "$VERSION_V1"

            echo "deb [signed-by=/usr/share/keyrings/microsandbox-archive-keyring.gpg] file:///repo-v2 stable main" \
                >/etc/apt/sources.list.d/microsandbox.list
            rm -rf /var/lib/apt/lists/*
            apt-get update
            apt-get install -y --only-upgrade microsandbox
            test "$(dpkg-query -W -f="\${Version}\n" microsandbox)" = "$VERSION_V2"

            apt-get remove -y microsandbox
            test ! -e /usr/bin/msb
            test -e /root/.microsandbox/state-marker

            apt-get install -y microsandbox
            apt-get purge -y microsandbox
            test ! -e /usr/bin/msb
            test -e /root/.microsandbox/state-marker
        '

    echo "==> Testing missing key failure in $image"
    docker run --rm \
        -e DEBIAN_FRONTEND=noninteractive \
        -v "$REPO_V1":/repo-v1:ro \
        "$image" \
        bash -euxo pipefail -c '
            echo "deb file:///repo-v1 stable main" >/etc/apt/sources.list.d/microsandbox.list
            if apt-get update; then
                echo "error: apt update succeeded without repository key" >&2
                exit 1
            fi
        '

    echo "==> Testing wrong key failure in $image"
    docker run --rm \
        -e DEBIAN_FRONTEND=noninteractive \
        -v "$REPO_V1":/repo-v1:ro \
        -v "$BAD_KEYRING":/tmp/wrong-keyring.gpg:ro \
        "$image" \
        bash -euxo pipefail -c '
            install -Dm644 /tmp/wrong-keyring.gpg \
                /usr/share/keyrings/microsandbox-archive-keyring.gpg
            echo "deb [signed-by=/usr/share/keyrings/microsandbox-archive-keyring.gpg] file:///repo-v1 stable main" \
                >/etc/apt/sources.list.d/microsandbox.list
            if apt-get update; then
                echo "error: apt update succeeded with the wrong repository key" >&2
                exit 1
            fi
        '
done
