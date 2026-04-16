#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: scripts/build-apt-repo.sh --input-dir <dir> --output-dir <dir> --gpg-key-id <id>

Build and sign a static APT repository from one or more `.deb` files.
EOF
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "error: required command not found: $1" >&2
        exit 1
    }
}

render_template() {
    local template="$1"
    shift

    local rendered
    rendered="$(<"$template")"

    while [[ $# -gt 0 ]]; do
        local key="$1"
        local value="$2"
        rendered="${rendered//${key}/${value}}"
        shift 2
    done

    printf '%s' "$rendered"
}

INPUT_DIR=""
OUTPUT_DIR=""
GPG_KEY_ID=""
DISTRIBUTION="stable"
SUITE="stable"
CODENAME="stable"
COMPONENT="main"
ORIGIN="microsandbox"
LABEL="microsandbox"
DESCRIPTION="Microsandbox APT repository"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --input-dir)
            INPUT_DIR="$2"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --gpg-key-id)
            GPG_KEY_ID="$2"
            shift 2
            ;;
        --distribution)
            DISTRIBUTION="$2"
            shift 2
            ;;
        --suite)
            SUITE="$2"
            shift 2
            ;;
        --codename)
            CODENAME="$2"
            shift 2
            ;;
        --component)
            COMPONENT="$2"
            shift 2
            ;;
        --origin)
            ORIGIN="$2"
            shift 2
            ;;
        --label)
            LABEL="$2"
            shift 2
            ;;
        --description)
            DESCRIPTION="$2"
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

[[ -n "$INPUT_DIR" && -n "$OUTPUT_DIR" && -n "$GPG_KEY_ID" ]] || {
    usage >&2
    exit 1
}

require_cmd apt-ftparchive
require_cmd dpkg-deb
require_cmd dpkg-scanpackages
require_cmd gpg
require_cmd gzip

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPLATE_DIR="$REPO_ROOT/packaging/apt"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$REPO_ROOT" log -1 --format=%ct 2>/dev/null || date +%s)}"

rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

POOL_DIR="$OUTPUT_DIR/pool/$COMPONENT/m/microsandbox"
DIST_DIR="$OUTPUT_DIR/dists/$DISTRIBUTION/$COMPONENT"
mkdir -p "$POOL_DIR" "$DIST_DIR"

mapfile -t DEBS < <(find "$INPUT_DIR" -maxdepth 1 -type f -name '*.deb' | sort)
[[ ${#DEBS[@]} -gt 0 ]] || {
    echo "error: no deb packages found in $INPUT_DIR" >&2
    exit 1
}

declare -A ARCH_SEEN=()
for deb in "${DEBS[@]}"; do
    cp "$deb" "$POOL_DIR/"
    arch="$(dpkg-deb -f "$deb" Architecture)"
    ARCH_SEEN["$arch"]=1
done

mapfile -t ARCHITECTURES < <(printf '%s\n' "${!ARCH_SEEN[@]}" | sort)
ARCHITECTURE_LIST="$(printf '%s ' "${ARCHITECTURES[@]}")"
ARCHITECTURE_LIST="${ARCHITECTURE_LIST% }"

for arch in "${ARCHITECTURES[@]}"; do
    BINARY_DIR="$DIST_DIR/binary-$arch"
    mkdir -p "$BINARY_DIR"
    (
        cd "$OUTPUT_DIR"
        dpkg-scanpackages -a "$arch" "pool/$COMPONENT/m/microsandbox" /dev/null
    ) >"$BINARY_DIR/Packages"
    gzip -n9 -c "$BINARY_DIR/Packages" >"$BINARY_DIR/Packages.gz"
done

RELEASE_CONFIG="$OUTPUT_DIR/apt-ftparchive-release.conf"
render_template \
    "$TEMPLATE_DIR/release.conf.template" \
    "@ORIGIN@" "$ORIGIN" \
    "@LABEL@" "$LABEL" \
    "@SUITE@" "$SUITE" \
    "@CODENAME@" "$CODENAME" \
    "@ARCHITECTURES@" "$ARCHITECTURE_LIST" \
    "@COMPONENTS@" "$COMPONENT" \
    "@DESCRIPTION@" "$DESCRIPTION" >"$RELEASE_CONFIG"

apt-ftparchive -c "$RELEASE_CONFIG" release "$OUTPUT_DIR/dists/$DISTRIBUTION" \
    >"$OUTPUT_DIR/dists/$DISTRIBUTION/Release"

GPG_COMMON_ARGS=(--batch --yes --pinentry-mode loopback --local-user "$GPG_KEY_ID")
if [[ -n "${APT_GPG_PASSPHRASE:-}" ]]; then
    GPG_COMMON_ARGS+=(--passphrase "$APT_GPG_PASSPHRASE")
fi

gpg "${GPG_COMMON_ARGS[@]}" \
    --output "$OUTPUT_DIR/dists/$DISTRIBUTION/Release.gpg" \
    --detach-sign "$OUTPUT_DIR/dists/$DISTRIBUTION/Release"

gpg "${GPG_COMMON_ARGS[@]}" \
    --output "$OUTPUT_DIR/dists/$DISTRIBUTION/InRelease" \
    --clearsign "$OUTPUT_DIR/dists/$DISTRIBUTION/Release"

gpg --batch --yes --output "$OUTPUT_DIR/microsandbox-archive-keyring.gpg" --export "$GPG_KEY_ID"
gpg --batch --yes --armor --output "$OUTPUT_DIR/microsandbox-archive-keyring.asc" --export "$GPG_KEY_ID"

while IFS= read -r -d '' path; do
    touch -h -d "@$SOURCE_DATE_EPOCH" "$path"
done < <(find "$OUTPUT_DIR" -print0)

printf '%s\n' "$OUTPUT_DIR"
