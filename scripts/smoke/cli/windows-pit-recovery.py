#!/usr/bin/env python3
"""Regression: recover a legacy Windows PIT-dependent snapshot, then recapture it.

Set MSB_PATH, MSB_HOME, MSB_LIBKRUNFW_PATH, LEGACY_WINDOWS_SNAPSHOT and
LEGACY_WINDOWS_PIT_DIVISOR. The fixture must be an actual older snapshot whose
clock stalls without PIT recovery (for example, a refined-jiffies guest).
The script preserves that fixture and stops all newly created sandboxes.
"""

import hashlib
import os
import subprocess
import time
import uuid
from pathlib import Path

exe = Path(os.environ["MSB_PATH"])
name = "pit-recovery-" + uuid.uuid4().hex[:6]
assert os.name == "nt", "requires a Windows x86 host"
assert os.environ.get("MSB_HOME"), (
    "set an isolated MSB_HOME containing the legacy snapshot"
)
snapshot = os.environ["LEGACY_WINDOWS_SNAPSHOT"]
divisor = os.environ["LEGACY_WINDOWS_PIT_DIVISOR"]
env = os.environ.copy()
print("SHA256", hashlib.sha256(exe.read_bytes()).hexdigest(), flush=True)


def run(*a, check=True):
    print("START", a, flush=True)
    start = time.monotonic()
    r = subprocess.run(
        [str(exe), *a], env=env, capture_output=True, timeout=60, check=False
    )
    print(
        "RESULT",
        r.returncode,
        round(time.monotonic() - start, 2),
        r.stdout.decode(errors="replace"),
        r.stderr.decode(errors="replace"),
        flush=True,
    )
    if check:
        assert r.returncode == 0
    return r


def check_clock(sandbox):
    def uptime():
        return float(
            run(
                "exec", sandbox, "--", "/bin/busybox", "cat", "/proc/uptime"
            ).stdout.split()[0]
        )

    before = uptime()
    run("exec", sandbox, "--", "/bin/busybox", "sleep", "1")
    assert uptime() > before, "guest clock stopped after restore"


try:
    r = run("snapshot", "restore", snapshot, "--name", name + "-reject", check=False)
    assert r.returncode != 0 and b"PIT timer state" in r.stderr + r.stdout
    run(
        "snapshot",
        "restore",
        snapshot,
        "--name",
        name,
        "--recover-windows-periodic-pit",
        divisor,
    )
    check_clock(name)
    run("snapshot", "create", "recaptured", "--from-sandbox", name, "--full")
    run("snapshot", "restore", name + ":recaptured", "--name", name + "-copy")
    check_clock(name + "-copy")
    run("snapshot", "create", "second", "--from-sandbox", name + "-copy", "--full")
    run(
        "snapshot",
        "restore",
        name + "-copy:second",
        "--name",
        name + "-second",
        "--cow-mem",
    )
    check_clock(name + "-second")
    print("RECOVERY_E2E_PASS", flush=True)
finally:
    for suffix in ["", "-reject", "-copy", "-second"]:
        run("stop", "--force", name + suffix, check=False)
