#!/usr/bin/env python3
"""Exercise the standalone script and Java trust through real sandbox execs.

Run with MSB_PATH and an isolated MSB_HOME. The runtime binary
must be runnable (codesigned on macOS). MSB_JAVA_IMAGE defaults to
'eclipse-temurin:17-jdk'; repeat with 'eclipse-temurin:25-jdk'. Requires HTTPS
access to example.com. Only this script's uniquely named sandboxes are removed.
"""

import os
import subprocess
import uuid
from pathlib import Path


BINARY = os.environ["MSB_PATH"]
assert os.environ.get("MSB_HOME"), "set an isolated MSB_HOME"
SCRIPT = Path(__file__).resolve().parents[2] / "msb-trust" / "msb-trust.sh"
GUEST_SCRIPT = "/usr/local/bin/msb-trust.sh"
IMAGE = os.environ.get("MSB_JAVA_IMAGE", "eclipse-temurin:17-jdk")
NAME = "java-trust-" + uuid.uuid4().hex[:12]
SOURCE = r'''
import java.io.FileInputStream;
import java.net.URI;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import java.util.TreeSet;
import javax.net.ssl.HttpsURLConnection;

class TrustProbe {
    public static void main(String[] args) throws Exception {
        if (args[0].equals("roots")) {
            var store = KeyStore.getInstance(KeyStore.getDefaultType());
            store.load(new FileInputStream(System.getProperty("java.home") +
                "/lib/security/cacerts"), "changeit".toCharArray());
            var roots = new TreeSet<String>();
            for (var aliases = store.aliases(); aliases.hasMoreElements();)
                roots.add(Base64.getEncoder().encodeToString(
                    store.getCertificate(aliases.nextElement()).getEncoded()));
            roots.forEach(System.out::println);
            return;
        }
        if (args[0].equals("ca")) {
            var ca = CertificateFactory.getInstance("X.509").generateCertificate(
                new FileInputStream("/.msb/tls/ca.pem"));
            System.out.println(Base64.getEncoder().encodeToString(ca.getEncoded()));
            return;
        }
        if (!"boot value".equals(System.getProperty("msb.option")))
            throw new Exception("Existing JVM options were lost");
        if (System.getProperty("javax.net.ssl.trustStore") != null)
            throw new Exception("The helper should not select a replacement store");
        var connection = (HttpsURLConnection) URI.create("https://example.com/").toURL().openConnection();
        connection.setConnectTimeout(15000);
        connection.setReadTimeout(15000);
        int status = connection.getResponseCode();
        if (status < 200 || status >= 400) throw new Exception("HTTP " + status);
        System.out.println("https-ok");
    }
}
'''


def run(*args, check=True):
    result = subprocess.run([BINARY, *args], text=True, capture_output=True, timeout=300)
    if check and result.returncode:
        raise AssertionError(f"{args}:\n{result.stdout}\n{result.stderr}")
    return result


def execute(*args, check=True, options=()):
    return run("exec", NAME, *options, "--", *args, check=check)


def probe(mode):
    return execute("java", "/tmp/TrustProbe.java", mode).stdout.strip()


def store_hash():
    return execute("sh", "-c", 'sha256sum "$JAVA_HOME/lib/security/cacerts"').stdout


def expect_failure(*args, message, options=()):
    result = execute(*args, check=False, options=options)
    assert result.returncode != 0, result.stdout
    assert message in result.stdout + result.stderr, result.stdout + result.stderr


created = False
try:
    run("create", IMAGE, "--name", NAME, "--memory", "1G", "--tls-intercept",
        "--net-rule", "allow@example.com", "--net-rule", "allow@dns",
        "--env", 'JAVA_TOOL_OPTIONS=-Dmsb.option="boot value"',
        "--copy-file", f"{SCRIPT}:{GUEST_SCRIPT}")
    created = True
    execute("sh", "-c", 'printf "%s" "$1" > /tmp/TrustProbe.java', "sh", SOURCE)
    execute("/bin/sh", GUEST_SCRIPT, "--help")
    execute("sh", "-lc", f"sh {GUEST_SCRIPT} --help")
    expect_failure("java", "/tmp/TrustProbe.java", "https", message="SunCertPathBuilderException")
    roots = set(probe("roots").splitlines())
    ca = probe("ca")
    assert len(roots) > 1 and ca not in roots
    before = store_hash()

    expect_failure("/bin/sh", GUEST_SCRIPT, "java", "python", message="unsupported application: python")
    expect_failure("/bin/sh", GUEST_SCRIPT, "java", message="keytool is not executable",
                   options=("--env", "JAVA_HOME=/missing-jdk"))
    expect_failure("/bin/sh", GUEST_SCRIPT, "java", message="java: keytool",
                   options=("--env", "JAVA_HOME=", "--env", "PATH=/missing-bin"))
    expect_failure("/bin/sh", GUEST_SCRIPT, "java", message="Java CA import failed",
                   options=("--user", "65534:65534"))
    assert store_hash() == before, "Failed imports changed the original trust store"
    print("PASS explicit opt-in and actionable failures without store mutation", flush=True)

    # Missing Chrome tools must not prevent the later Java setup; repeated names
    # should produce only one missing-tool entry and one combined retry command.
    selected = execute("/bin/sh", GUEST_SCRIPT, "chrome", "java", "chrome", check=False)
    assert selected.returncode != 0
    assert "Configured:\n  java" in selected.stdout
    assert selected.stdout.count("chrome: certutil") == 1
    assert selected.stdout.count("Then rerun:") == 1
    assert "sh msb-trust.sh chrome java" in selected.stdout
    assert probe("https") == "https-ok"
    print("PASS explicit selections continue after missing tools and return failure", flush=True)

    summary = execute("/bin/sh", GUEST_SCRIPT, "all").stdout
    assert "Configured:\n  java" in summary
    assert summary.count("Then rerun:") == 1
    assert "apt-get update && apt-get install -y libnss3-tools" in summary
    assert "dnf install" not in summary
    assert set(probe("roots").splitlines()) == roots | {ca}, "Existing roots changed"
    assert probe("https") == "https-ok"
    after = store_hash()
    assert execute("/bin/sh", GUEST_SCRIPT, "java", "java").stdout.count("already trusts") == 1
    assert store_hash() == after, "Repeated invocation rewrote the store"
    assert "already trusts" in execute("/bin/sh", GUEST_SCRIPT, "java", options=("--env", "JAVA_HOME=")).stdout

    # The patched script and imported trust survive a cold restart.
    run("stop", NAME)
    run("start", NAME)
    execute("/bin/sh", GUEST_SCRIPT, "--help")
    assert probe("https") == "https-ok"
    assert "already trusts" in execute("/bin/sh", GUEST_SCRIPT, "java").stdout
    print("PASS preserved roots/options, intercepted HTTPS, repeat call, and cold restart", flush=True)

    # A different certificate under the reserved alias must not be deleted silently.
    execute("keytool", "-delete", "-cacerts", "-alias", "microsandbox-interception",
            "-storepass", "changeit")
    execute("keytool", "-genkeypair", "-alias", "unrelated", "-dname", "CN=Unrelated",
            "-keyalg", "RSA", "-validity", "1", "-keystore", "/tmp/unrelated.p12",
            "-storepass", "changeit")
    execute("keytool", "-exportcert", "-alias", "unrelated", "-keystore", "/tmp/unrelated.p12",
            "-storepass", "changeit", "-file", "/tmp/unrelated.der")
    execute("keytool", "-importcert", "-noprompt", "-cacerts", "-alias", "microsandbox-interception",
            "-file", "/tmp/unrelated.der", "-storepass", "changeit")
    conflicting = store_hash()
    expect_failure("/bin/sh", GUEST_SCRIPT, "java", message="contains a different certificate")
    assert store_hash() == conflicting
    print("PASS conflicting alias preserves existing trust", flush=True)

    # Some JDKs ship passwordless stores. Use an explicitly protected JKS store
    # to exercise both the wrong-password error and password environment option.
    execute("keytool", "-importkeystore", "-noprompt", "-srckeystore", "/tmp/unrelated.p12",
            "-srcstorepass", "changeit", "-destkeystore", "/tmp/protected.jks",
            "-deststoretype", "JKS", "-deststorepass", "custom-password")
    execute("sh", "-c", 'cp /tmp/protected.jks "$JAVA_HOME/lib/security/cacerts"')
    protected = store_hash()
    expect_failure("/bin/sh", GUEST_SCRIPT, "java", message="Java CA import failed")
    assert store_hash() == protected
    execute("/bin/sh", GUEST_SCRIPT, "java", options=("--env", "MSB_JAVA_STORE_PASSWORD=custom-password"))
    assert "already trusts" in execute("/bin/sh", GUEST_SCRIPT, "java", options=(
        "--env", "MSB_JAVA_STORE_PASSWORD=custom-password")).stdout
    print("PASS explicit store password and failed-password safety", flush=True)
finally:
    if created:
        run("remove", "--force", NAME)

# The helper remains usable for diagnostics in images without Java or interception.
NAME += "-plain"
created = False
try:
    run("create", "alpine:3.21", "--name", NAME,
        "--copy-file", f"{SCRIPT}:{GUEST_SCRIPT}")
    created = True
    execute("/bin/sh", GUEST_SCRIPT, "--help")
    summary = execute("/bin/sh", GUEST_SCRIPT, "all").stdout
    assert "No applications configured." in summary
    assert "java: keytool" in summary and "chrome: certutil" in summary
    assert summary.count("Then rerun:") == 1
    assert "sh msb-trust.sh all" in summary
    assert "apt-get" not in summary and "dnf install" not in summary
    expect_failure("/bin/sh", GUEST_SCRIPT, "java", message="enable TLS interception first")
    print("PASS shell-only image and interception-disabled diagnostic", flush=True)
finally:
    if created:
        run("remove", "--force", NAME)
