#!/usr/bin/env bash

if [[ -n "${MICROSANDBOX_APT_COMMON_SH_LOADED:-}" ]]; then
    return 0
fi
MICROSANDBOX_APT_COMMON_SH_LOADED=1

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "error: required command not found: $1" >&2
        exit 1
    }
}

map_deb_arch() {
    case "$1" in
        amd64 | x86_64) printf '%s\n' "amd64" ;;
        arm64 | aarch64) printf '%s\n' "arm64" ;;
        *)
            echo "error: unsupported Debian architecture: $1" >&2
            exit 1
            ;;
    esac
}

normalize_deb_version() {
    local raw="$1"
    local revision="${2:-1}"
    local clean="${raw#v}"

    if [[ "$clean" == *-* ]]; then
        printf '%s\n' "$clean"
        return
    fi

    printf '%s-%s\n' "$clean" "$revision"
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
