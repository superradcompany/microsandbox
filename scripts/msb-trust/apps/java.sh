# Java

java_description() { printf "Import the CA into the JDK's default trust store\n"; }
java_tools() { printf 'keytool\n'; }
java_packages() { :; } # The user must select the JDK their application uses.

java_available() {
    # An explicit JAVA_HOME is configuration to validate, not an absent app.
    [ -n "${JAVA_HOME:-}" ] || command -v keytool >/dev/null 2>&1
}

java_install_hint() {
    printf 'For Java, install a JDK with keytool, or set JAVA_HOME to your existing JDK.\n'
}

java_help() {
    cat <<'HELP'
Usage: sh msb-trust.sh java

Import the sandbox's TLS interception CA into the JDK's default trust store.
Uses $JAVA_HOME/bin/keytool when JAVA_HOME is set, otherwise keytool on PATH.
Requires write access to the store. Existing certificates are preserved.

Set MSB_JAVA_STORE_PASSWORD if the store password is not "changeit".
Applications with a custom trust store need to import the CA into that store.

For a read-only JDK:
  1. Copy the JDK's lib/security/cacerts to a writable file.
  2. Import the CA into that copy:
     keytool -importcert -noprompt -alias microsandbox-interception \
       -file /.msb/tls/ca.pem -keystore /path/to/cacerts
  3. Set -Djavax.net.ssl.trustStore=/path/to/cacerts when launching Java.
     If using JAVA_TOOL_OPTIONS, keep any existing options and configure it
     for future sandbox execs, not just the setup script's shell.

Restart Java processes and Gradle daemons after changing trust.
HELP
}

java_configure() {
    if [ -n "${JAVA_HOME:-}" ]; then
        keytool=$JAVA_HOME/bin/keytool
        [ -x "$keytool" ] || fail "keytool is not executable at $keytool; set JAVA_HOME to your application's JDK"
    else
        keytool=$(command -v keytool) || {
            fail "keytool not found"
        }
    fi

    # Pass the password through the environment, not the process arguments.
    MSB_JAVA_STORE_PASSWORD=${MSB_JAVA_STORE_PASSWORD-changeit}
    export MSB_JAVA_STORE_PASSWORD
    alias=microsandbox-interception

    if existing=$("$keytool" -exportcert -rfc -cacerts -alias "$alias" \
        -storepass:env MSB_JAVA_STORE_PASSWORD 2>/dev/null); then
        expected=$(certificate_data < "$CA_CERT") || fail "cannot read sandbox CA"
        actual=$(printf '%s\n' "$existing" | certificate_data) || fail "cannot read existing certificate"
        if [ "$actual" = "$expected" ]; then
            progress 'Java already trusts this sandbox CA'
            return
        fi

        fail "alias $alias contains a different certificate; review it with keytool -list -cacerts -alias $alias, then remove that alias explicitly before retrying"
    fi

    if ! import_output=$("$keytool" -importcert -noprompt -cacerts -alias "$alias" \
        -file "$CA_CERT" -storepass:env MSB_JAVA_STORE_PASSWORD 2>&1); then
        printf '%s\n' "$import_output" >&2
        fail "Java CA import failed; check write permissions or set MSB_JAVA_STORE_PASSWORD for a non-default password. For read-only or custom stores, run: sh msb-trust.sh java --help"
    fi

    progress 'imported sandbox CA into the JDK trust store; restart existing Java processes to use it'
}
