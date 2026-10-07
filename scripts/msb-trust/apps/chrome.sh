# Chrome/Chromium

chrome_description() { printf "Import the CA into the current user's Chrome/Chromium NSS store\n"; }
chrome_tools() { printf 'certutil\n'; }
chrome_packages() {
    case "$1" in
        apt-get) printf 'libnss3-tools\n' ;;
        dnf) printf 'nss-tools\n' ;;
    esac
}

chrome_help() {
    cat <<'HELP'
Usage: sh msb-trust.sh chrome

Import the sandbox CA into the current user's Chrome/Chromium NSS store.
Requires certutil (libnss3-tools on Debian/Ubuntu, nss-tools on Fedora).
Close the browser first. Run as the browser's user, with HOME set accordingly.

Uses an existing ~/.pki/nssdb before ~/.local/share/pki/nssdb, matching Chrome.
For a fresh home, creates ~/.pki/nssdb for compatibility with older browsers.
Existing certificates are preserved. Password-protected stores require manual setup.
Use certutil interactively for those stores:
  certutil -A -d sql:/path/to/nssdb -n microsandbox-interception \
    -t 'C,,' -i /.msb/tls/ca.pem
Restart the browser after changing trust.
HELP
}

chrome_configure() {
    command -v certutil >/dev/null 2>&1 || {
        fail "certutil not found"
    }
    case "${HOME:-}" in
        /*) ;;
        *) fail "set HOME to the browser user's absolute home directory" ;;
    esac

    store=$HOME/.pki/nssdb
    if [ ! -d "$store" ] && [ -d "$HOME/.local/share/pki/nssdb" ]; then
        store=$HOME/.local/share/pki/nssdb
    fi
    alias=microsandbox-interception
    progress "configuring $store; use the browser's user and HOME, with the browser closed"

    # Only initialize an empty directory; never reset an existing NSS database.
    if [ ! -f "$store/cert9.db" ]; then
        (umask 077; mkdir -p "$store") || fail "cannot create NSS store at $store"
        contents=$(ls -A "$store") || fail "cannot inspect NSS directory $store"
        [ -z "$contents" ] || fail "NSS directory $store is not empty but has no cert9.db; inspect it before retrying"
        certutil -N -d "sql:$store" --empty-password || fail "cannot initialize NSS store at $store"
    fi
    certificates=$(certutil -L -d "sql:$store") || fail "cannot read NSS store at $store"

    if existing=$(certutil -L -d "sql:$store" -n "$alias" -a 2>/dev/null); then
        expected=$(certificate_data < "$CA_CERT") || fail "cannot read sandbox CA"
        actual=$(printf '%s\n' "$existing" | certificate_data) || fail "cannot read existing certificate"
        [ "$actual" = "$expected" ] || fail "alias $alias contains a different certificate in $store; review and remove that alias explicitly before retrying"

        trust=$(printf '%s\n' "$certificates" | awk -v name="$alias" '$1 == name { print $NF }') || fail "cannot read NSS trust flags"
        case "${trust%%,*}" in
            *C*) progress 'Chrome/Chromium already trusts this sandbox CA'; return ;;
        esac
        certutil -M -d "sql:$store" -n "$alias" -t "C,," -f /dev/null || fail "cannot update NSS trust; check write permissions. For password-protected stores, run: sh msb-trust.sh chrome --help"
    else
        certutil -A -d "sql:$store" -n "$alias" -t "C,," -i "$CA_CERT" -f /dev/null || fail "Chrome CA import failed; check write permissions. For password-protected stores, run: sh msb-trust.sh chrome --help"
    fi

    progress "imported sandbox CA into $store; restart Chrome/Chromium to use it"
}
