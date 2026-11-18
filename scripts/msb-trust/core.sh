# Shared application selection, dependency reporting, and command dispatch.
CA_CERT=/.msb/tls/ca.pem

fail() {
    printf 'msb-trust: %s\n' "$*" >&2
    exit 1
}

usage() (
    cat <<'HELP'
Usage: sh msb-trust.sh <application> [application ...]
       sh msb-trust.sh all

Configure application trust stores to trust the sandbox's TLS interception CA.
Name the applications to configure, or use all for supported applications whose
tools are installed. Every selected application is attempted; successful imports
remain in place if another application fails. Missing tools are summarized with
installation instructions and one retry command. Packages are not installed.
Exit status is nonzero if setup fails or an explicitly requested app lacks tools.
With all, missing tools are skipped without making the command fail.

Supported applications:
HELP
    for application in $SUPPORTED_APPLICATIONS; do
        printf '  %s' "$application"
        if command -v "${application}_description" >/dev/null 2>&1; then
            printf '  %s' "$("${application}_description")"
        fi
        printf '\n'
    done
    printf '\nRun sh msb-trust.sh <application> --help for application-specific requirements.\n'
)

require_ca() {
    [ -r "$CA_CERT" ] || fail "no readable interception CA at $CA_CERT; enable TLS interception first"
}

# Compare the first PEM certificate, ignoring surrounding comments and metadata.
certificate_data() {
    awk '
        /-----BEGIN CERTIFICATE-----/ { inside = 1; next }
        /-----END CERTIFICATE-----/ {
            if (inside && length(data)) { print data; found = 1 }
            exit
        }
        inside { gsub(/[[:space:]]/, ""); data = data $0 }
        END { if (!found) exit 1 }
    '
}

application_supported() (
    for candidate in $SUPPORTED_APPLICATIONS; do
        [ "$1" != "$candidate" ] || return 0
    done
    return 1
)

application_missing_tools() (
    missing=
    for tool in $("${1}_tools"); do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing="${missing:+$missing }$tool"
        fi
    done
    printf '%s\n' "$missing"
)

application_available() (
    if command -v "${1}_available" >/dev/null 2>&1; then
        "${1}_available"
    else
        [ -z "$(application_missing_tools "$1")" ]
    fi
)

unique_words() (
    seen=" "
    for word do
        case "$seen" in
            *" $word "*) continue ;;
        esac
        printf '%s\n' "$word"
        seen="$seen$word "
    done
)

missing_tools() (
    manager=
    for candidate in apt-get dnf; do
        if command -v "$candidate" >/dev/null 2>&1; then
            manager=$candidate
            break
        fi
    done

    printf 'Missing tools:\n'
    for application do
        printf '  %s: %s\n' "$application" "$(application_missing_tools "$application")"
    done

    printf '\nInstall only the tools for applications you use.\n'
    packages=
    unmapped_tools=
    for application do
        dependencies=$(application_missing_tools "$application")
        # Hook output contains fixed command/package names, never user input.
        # shellcheck disable=SC2086
        application_packages=$("${application}_packages" "$manager" $dependencies)
        if [ -n "$application_packages" ]; then
            packages="$packages $application_packages"
        fi
        if command -v "${application}_install_hint" >/dev/null 2>&1; then
            ("${application}_install_hint")
        elif [ -z "$application_packages" ]; then
            unmapped_tools="$unmapped_tools $dependencies"
        fi
    done
    # shellcheck disable=SC2086
    for tool in $(unique_words $unmapped_tools); do
        printf 'Install %s using your distribution package manager.\n' "$tool"
    done

    if [ -n "$packages" ]; then
        printf '\nInstall missing packages as root:\n  '
        case "$manager" in
            apt-get) printf 'apt-get update && apt-get install -y' ;;
            dnf) printf 'dnf install -y' ;;
        esac
        # shellcheck disable=SC2086
        for package in $(unique_words $packages); do
            printf ' %s' "$package"
        done
        printf '\n'
    fi
)

progress() {
    if [ "$batch" = false ]; then
        printf 'msb-trust: %s\n' "$*"
    fi
}

main() {
    [ "$#" -gt 0 ] || { usage >&2; exit 2; }
    if [ "$#" -eq 1 ]; then
        case "$1" in
            -h|--help) usage; return ;;
        esac
    elif [ "$#" -eq 2 ]; then
        case "$2" in
            -h|--help)
                application_supported "$1" || fail "unsupported application: $1"
                "${1}_help"
                return
                ;;
        esac
    fi

    all=false
    if [ "$1" = all ]; then
        [ "$#" -eq 1 ] || { usage >&2; exit 2; }
        all=true
        # The registry contains fixed application names, not user input.
        # shellcheck disable=SC2086
        set -- $SUPPORTED_APPLICATIONS
    fi

    # Validate the whole request before changing any trust store.
    for application do
        if ! application_supported "$application"; then
            usage >&2
            fail "unsupported application: $application"
        fi
    done

    # Requests are validated before splitting and deduplicating these fixed names.
    # shellcheck disable=SC2046
    set -- $(unique_words "$@")
    retry="$*"
    batch=false
    if [ "$all" = true ]; then
        retry=all
        batch=true
    elif [ "$#" -gt 1 ]; then
        batch=true
    fi

    # A missing CA affects the whole explicit request, not an individual app.
    if [ "$all" = false ]; then
        require_ca
    fi

    configured=
    missing=
    failed=
    status=0
    for application do
        if ! application_available "$application"; then
            missing="$missing $application"
            if [ "$all" = false ]; then
                status=1
            fi
            continue
        fi

        require_ca
        # Handlers explicitly guard fallible operations: conditional calls disable
        # errexit. A handler failure must not stop the remaining applications.
        if ("${application}_configure"); then
            configured="$configured $application"
        else
            failed="$failed $application"
            status=1
        fi
    done

    if [ "$batch" = true ]; then
        if [ -z "$configured" ]; then
            printf 'No applications configured.\n'
        else
            printf 'Configured:\n'
            for application in $configured; do
                printf '  %s\n' "$application"
            done
            printf '\nRestart configured applications to use the updated trust stores.\n'
        fi
    fi
    if [ -n "$failed" ]; then
        printf '\nFailed:\n'
        for application in $failed; do
            printf '  %s (see error above)\n' "$application"
        done
    fi
    if [ -n "$missing" ]; then
        printf '\n'
        # shellcheck disable=SC2086
        missing_tools $missing
    fi
    if [ -n "$missing$failed" ]; then
        printf '\nThen rerun:\n  sh msb-trust.sh %s\n' "$retry"
    fi
    return "$status"
}
