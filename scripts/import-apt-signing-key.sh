#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/apt-common.sh
source "$SCRIPT_DIR/lib/apt-common.sh"

usage() {
    cat <<'EOF'
Usage: scripts/import-apt-signing-key.sh --gnupg-home <dir> [--private-key-file <path>]

Import the production APT signing key into a dedicated GnuPG home and print the
fingerprint. The private key can come from `--private-key-file`,
`APT_GPG_PRIVATE_KEY`, or `APT_GPG_PRIVATE_KEY_BASE64`.
EOF
}

GNUPG_HOME=""
PRIVATE_KEY_FILE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --gnupg-home)
            GNUPG_HOME="$2"
            shift 2
            ;;
        --private-key-file)
            PRIVATE_KEY_FILE="$2"
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

[[ -n "$GNUPG_HOME" ]] || {
    usage >&2
    exit 1
}

require_cmd gpg

mkdir -p "$GNUPG_HOME"
chmod 700 "$GNUPG_HOME"

TEMP_KEY_FILE=""
cleanup() {
    if [[ -n "$TEMP_KEY_FILE" && -f "$TEMP_KEY_FILE" ]]; then
        rm -f "$TEMP_KEY_FILE"
    fi
}
trap cleanup EXIT

if [[ -z "$PRIVATE_KEY_FILE" ]]; then
    if [[ -n "${APT_GPG_PRIVATE_KEY:-}" ]]; then
        TEMP_KEY_FILE="$(mktemp)"
        printf '%s\n' "$APT_GPG_PRIVATE_KEY" >"$TEMP_KEY_FILE"
        PRIVATE_KEY_FILE="$TEMP_KEY_FILE"
    elif [[ -n "${APT_GPG_PRIVATE_KEY_BASE64:-}" ]]; then
        TEMP_KEY_FILE="$(mktemp)"
        printf '%s' "$APT_GPG_PRIVATE_KEY_BASE64" | base64 --decode >"$TEMP_KEY_FILE"
        PRIVATE_KEY_FILE="$TEMP_KEY_FILE"
    fi
fi

[[ -n "$PRIVATE_KEY_FILE" && -f "$PRIVATE_KEY_FILE" ]] || {
    echo "error: no signing key provided" >&2
    exit 1
}

gpg --homedir "$GNUPG_HOME" --batch --import "$PRIVATE_KEY_FILE" >/dev/null 2>&1
FINGERPRINT="$(
    gpg --homedir "$GNUPG_HOME" --batch --with-colons --list-secret-keys |
        awk -F: '$1 == "fpr" { print $10; exit }'
)"

[[ -n "$FINGERPRINT" ]] || {
    echo "error: imported key fingerprint could not be determined" >&2
    exit 1
}

echo "$FINGERPRINT:6:" | gpg --homedir "$GNUPG_HOME" --batch --import-ownertrust >/dev/null 2>&1
printf '%s\n' "$FINGERPRINT"
