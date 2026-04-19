#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/apt-common.sh
source "$SCRIPT_DIR/lib/apt-common.sh"

usage() {
    cat <<'EOF'
Usage: scripts/generate-apt-test-key.sh --gnupg-home <dir>

Generate an ephemeral unprotected signing key for CI/package tests.
EOF
}

GNUPG_HOME=""
NAME_REAL="Microsandbox Test Repository"
NAME_EMAIL="ci@microsandbox.dev"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --gnupg-home)
            GNUPG_HOME="$2"
            shift 2
            ;;
        --name-real)
            NAME_REAL="$2"
            shift 2
            ;;
        --name-email)
            NAME_EMAIL="$2"
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

cat >"$GNUPG_HOME/key.conf" <<EOF
%no-protection
Key-Type: RSA
Key-Length: 3072
Subkey-Type: RSA
Subkey-Length: 3072
Name-Real: $NAME_REAL
Name-Email: $NAME_EMAIL
Expire-Date: 0
%commit
EOF

gpg --homedir "$GNUPG_HOME" --batch --generate-key "$GNUPG_HOME/key.conf" >/dev/null 2>&1
FINGERPRINT="$(
    gpg --homedir "$GNUPG_HOME" --batch --with-colons --list-secret-keys "$NAME_EMAIL" |
        awk -F: '$1 == "fpr" { print $10; exit }'
)"

echo "$FINGERPRINT:6:" | gpg --homedir "$GNUPG_HOME" --batch --import-ownertrust >/dev/null 2>&1
printf '%s\n' "$FINGERPRINT"
