#!/usr/bin/env python3
"""Test msb-trust.sh with real headless Chrome and NSS stores in a disposable VM.

Set MSB_PATH and an isolated MSB_HOME. Requires network access to Debian package
mirrors, dl.google.com, and example.com. Installs official stable Chrome for the
guest architecture. No certificate-verification bypass flags are used.
"""

import os
import subprocess
import uuid
from pathlib import Path


BINARY = os.environ["MSB_PATH"]
assert os.environ.get("MSB_HOME"), "set an isolated MSB_HOME"
SCRIPT = Path(__file__).resolve().parents[2] / "msb-trust" / "msb-trust.sh"
GUEST_SCRIPT = "/usr/local/bin/msb-trust.sh"
NAME = "chrome-trust-" + uuid.uuid4().hex[:12]
HOME = "/home/browser"


def run(*args, check=True):
    result = subprocess.run([BINARY, *args], text=True, capture_output=True, timeout=360)
    if check and result.returncode:
        raise AssertionError(f"{args}:\n{result.stdout}\n{result.stderr}")
    return result


def execute(*args, home=HOME, check=True):
    return run("exec", NAME, "--user", "browser", "--env", f"HOME={home}",
               "--timeout", "60s", "--", *args, check=check)


def setup(*apps, home=HOME, check=True):
    return execute("sh", GUEST_SCRIPT, *apps, home=home, check=check)


def browse(url, home=HOME):
    # Browser process isolation is separate from TLS verification; the VM provides
    # isolation for this disposable probe. Every launch uses a fresh browser profile.
    return execute("google-chrome-stable", "--headless", "--no-sandbox",
                   "--disable-gpu", "--disable-dev-shm-usage", "--no-first-run",
                   "--disable-background-networking",
                   f"--user-data-dir={home}/profile-{uuid.uuid4().hex}",
                   "--dump-dom", url, home=home)


def assert_page(result):
    assert "<title>Example Domain</title>" in result.stdout, result.stderr
    assert "ERR_CERT_AUTHORITY_INVALID" not in result.stdout + result.stderr


def store_hash(store):
    return execute("sha256sum", f"{store}/cert9.db").stdout


created = False
try:
    run("create", "debian:bookworm-slim", "--name", NAME, "--memory", "2G",
        "--cpus", "2", "--tls-intercept", "--tls-bypass", "www.example.com",
        "--copy-file", f"{SCRIPT}:{GUEST_SCRIPT}")
    created = True
    run("exec", NAME, "--timeout", "5m", "--", "sh", "-ec", '''
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends ca-certificates curl openssl libnss3-tools
arch=$(dpkg --print-architecture)
curl -fsSL "https://dl.google.com/linux/direct/google-chrome-stable_current_${arch}.deb" -o /tmp/chrome.deb
apt-get install -y -qq --no-install-recommends /tmp/chrome.deb
rm /tmp/chrome.deb
useradd -m browser
''')
    print(execute("google-chrome-stable", "--version").stdout.strip(), flush=True)
    assert_page(browse("https://www.example.com/"))
    before = browse("https://example.com/")
    assert "ERR_CERT_AUTHORITY_INVALID" in before.stdout + before.stderr
    print("PASS interception fails certificate validation before setup", flush=True)

    # Chrome has already created its modern database. The script must use it.
    modern = f"{HOME}/.local/share/pki/nssdb"
    execute("test", "-f", f"{modern}/cert9.db")
    # An invalid explicit Java configuration must fail without preventing Chrome
    # from importing the CA. The combined command still reports failure.
    selected = execute("env", "JAVA_HOME=/missing-jdk", "sh", GUEST_SCRIPT,
                       "java", "chrome", check=False)
    assert selected.returncode != 0
    assert "keytool is not executable" in selected.stderr
    assert "Configured:\n  chrome" in selected.stdout
    assert "Failed:\n  java" in selected.stdout
    assert selected.stdout.count("Then rerun:") == 1
    assert "sh msb-trust.sh java chrome" in selected.stdout
    execute("certutil", "-L", "-d", f"sql:{modern}", "-n", "microsandbox-interception")
    assert_page(browse("https://example.com/"))
    # all may skip missing tools, but an actual configuration error still fails.
    failed_all = execute("env", "JAVA_HOME=/missing-jdk", "sh", GUEST_SCRIPT,
                         "all", check=False)
    assert failed_all.returncode != 0
    assert "Configured:\n  chrome" in failed_all.stdout
    setup("all")
    assert_page(browse("https://example.com/"))
    unchanged = store_hash(modern)
    assert "already trusts" in setup("chrome", "chrome").stdout
    assert store_hash(modern) == unchanged
    print("PASS existing modern store, HTTPS, and repeat setup without rewriting trust", flush=True)

    # Test pre-browser setup with a fresh home and keep unrelated trust intact.
    fresh = f"{HOME}/fresh"
    setup("chrome", home=fresh)
    legacy = f"{fresh}/.pki/nssdb"
    execute("test", "-f", f"{legacy}/cert9.db")
    assert_page(browse("https://example.com/", home=fresh))
    execute("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", f"{HOME}/other.key", "-out", f"{HOME}/other.pem",
            "-subj", "/CN=Unrelated", "-days", "1")
    execute("certutil", "-A", "-d", f"sql:{legacy}", "-n", "unrelated",
            "-t", "C,,", "-i", f"{HOME}/other.pem")
    unchanged = store_hash(legacy)
    setup("chrome", home=fresh)
    assert store_hash(legacy) == unchanged
    execute("certutil", "-L", "-d", f"sql:{legacy}", "-n", "unrelated")
    print("PASS fresh store works and preserves unrelated certificates", flush=True)

    # A matching certificate lacking CA trust must be repaired, not skipped.
    execute("certutil", "-M", "-d", f"sql:{legacy}", "-n", "microsandbox-interception", "-t", ",,")
    setup("chrome", home=fresh)
    assert_page(browse("https://example.com/", home=fresh))

    # Refuse to overwrite an unrelated certificate using the script's alias.
    # NSS identifies certificates by content, so use a certificate not already
    # present under another nickname in this store.
    execute("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", f"{HOME}/conflict.key", "-out", f"{HOME}/conflict.pem",
            "-subj", "/CN=Conflicting", "-days", "1")
    execute("certutil", "-D", "-d", f"sql:{legacy}", "-n", "microsandbox-interception")
    execute("certutil", "-A", "-d", f"sql:{legacy}", "-n", "microsandbox-interception",
            "-t", "C,,", "-i", f"{HOME}/conflict.pem")
    unchanged = store_hash(legacy)
    conflict = setup("chrome", home=fresh, check=False)
    assert conflict.returncode != 0
    assert "different certificate" in conflict.stdout + conflict.stderr
    assert store_hash(legacy) == unchanged
    print("PASS trust flags repaired and conflicting alias left untouched", flush=True)

    run("stop", NAME)
    run("start", NAME)
    assert_page(browse("https://example.com/"))
    print("PASS imported trust survives sandbox stop/start", flush=True)
finally:
    if created:
        run("remove", "--force", NAME)
