#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: scripts/apt-smoke-test.sh --repo-url <url> [--keyring-path <path> | --key-url <url>]

Install microsandbox from an APT repository and run a short end-to-end CLI smoke
test on a Linux host with KVM.
EOF
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "error: required command not found: $1" >&2
        exit 1
    }
}

REPO_URL=""
KEYRING_PATH=""
KEY_URL=""
DISTRIBUTION="stable"
PACKAGE_NAME="microsandbox"
KEYRING_DEST="/usr/share/keyrings/microsandbox-archive-keyring.gpg"
SOURCE_LIST="/etc/apt/sources.list.d/microsandbox.list"
SANDBOX_NAME="apt-smoke"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --repo-url)
            REPO_URL="$2"
            shift 2
            ;;
        --keyring-path)
            KEYRING_PATH="$2"
            shift 2
            ;;
        --key-url)
            KEY_URL="$2"
            shift 2
            ;;
        --distribution)
            DISTRIBUTION="$2"
            shift 2
            ;;
        --package)
            PACKAGE_NAME="$2"
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

[[ -n "$REPO_URL" ]] || {
    usage >&2
    exit 1
}

if [[ -z "$KEYRING_PATH" && -z "$KEY_URL" ]]; then
    usage >&2
    exit 1
fi

require_cmd sudo
require_cmd apt-get
require_cmd timeout

cleanup() {
    msb stop "$SANDBOX_NAME" >/dev/null 2>&1 || true
    msb rm "$SANDBOX_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

if [[ -n "$KEYRING_PATH" ]]; then
    sudo install -Dm644 "$KEYRING_PATH" "$KEYRING_DEST"
else
    require_cmd curl
    curl -fsSL "$KEY_URL" | sudo tee "$KEYRING_DEST" >/dev/null
fi

echo "deb [signed-by=$KEYRING_DEST] $REPO_URL $DISTRIBUTION main" | \
    sudo tee "$SOURCE_LIST" >/dev/null

sudo apt-get update
sudo apt-get install -y "$PACKAGE_NAME"

timeout 600 msb run --name "$SANDBOX_NAME" alpine -- sh -lc 'echo apt smoke hello'
timeout 600 msb start "$SANDBOX_NAME"
timeout 600 msb exec "$SANDBOX_NAME" -- sh -lc 'uname -a'
timeout 600 msb stop "$SANDBOX_NAME"
timeout 600 msb rm "$SANDBOX_NAME"
