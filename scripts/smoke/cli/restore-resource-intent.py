#!/usr/bin/env python3
"""Live full-restore resource-intent regression matrix in an isolated MSB_HOME.

Set MSB_PATH, MSB_AGENTD_PATH, MSB_LIBKRUNFW_PATH and RESTORE_INTENT_OUT.
Optional RESTORE_INTENT_LAYOUT selects flat:512M (default) or 512M (layered).
Every invocation uses EOF stdin, including detached Windows test launchers.
"""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import time


binary = os.environ["MSB_PATH"]
root = Path(os.environ["RESTORE_INTENT_OUT"])
root.mkdir(parents=True, exist_ok=False)
home = root / "home"
env = dict(os.environ, MSB_HOME=str(home))
image = os.environ.get("MSB_TEST_IMAGE", "mirror.gcr.io/library/alpine:latest")
layout = os.environ.get("RESTORE_INTENT_LAYOUT", "flat:512M")
rows = []
names = []


def run(label, *args, fail=False):
    started = time.perf_counter()
    command = [binary, *map(str, args)]
    try:
        result = subprocess.run(command, env=env, input="", capture_output=True,
                                text=True, timeout=180)
    except subprocess.TimeoutExpired:
        rows.append({"case": label, "argv": command, "exit": "timeout",
                     "ms": round((time.perf_counter() - started) * 1000, 2)})
        raise
    row = {"case": label, "argv": command, "exit": result.returncode,
           "ms": round((time.perf_counter() - started) * 1000, 2)}
    rows.append(row)
    print(json.dumps(row), flush=True)
    (root / (label + ".stdout")).write_text(result.stdout)
    (root / (label + ".stderr")).write_text(result.stderr)
    if (result.returncode != 0) != fail:
        raise AssertionError(f"{label}: {result.stderr[-3000:]}")
    return result


def verify_child(name, ram=True, memory=512):
    inspected = json.loads(run(name + "-inspect", "inspect", name, "--format", "json").stdout)
    resources = inspected["config"]["resources"]
    assert resources["memory_mib"] == memory, resources
    if ram:
        assert resources["cpus"] == resources["max_cpus"] == 2, resources
        assert resources["max_memory_mib"] == 512, resources
    guest = run(name + "-markers", "exec", "--no-tty", name, "--", "sh", "-ec",
                "test \"$(cat /disk-marker)\" = disk-preserved; "
                + ("test \"$(cat /dev/shm/marker)\" = ram-preserved" if ram
                   else "test ! -e /dev/shm/marker"))
    assert guest.returncode == 0


success = False
try:
    names.append("source")
    run("source-create", "create", image, "--name", "source", "--root-disk", layout,
        "--memory", "512M", "--cpus", "2")
    run("source-markers", "exec", "--no-tty", "source", "--", "sh", "-ec",
        "echo disk-preserved > /disk-marker; echo ram-preserved > /dev/shm/marker; sync")
    saved = run("capture", "snapshot", "create", "saved", "--from-sandbox", "source", "--full")
    member = Path(saved.stdout.strip().splitlines()[-1])
    descriptor_hash = hashlib.sha256((member / "snapshot.json").read_bytes()).hexdigest()
    archive = root / "saved.msb"
    run("save", "snapshot", "save", member, archive)
    # Dedicated restore accepts explicit geometry controls, not create-time config files.
    cases = {
        "absent": [],
        "matching": ["--cpus", "2", "--memory", "512M"],
        "smaller": ["--memory", "128M"],
        "larger": ["--memory", "1G"],
        "cpus": ["--cpus", "1"],
        "short-memory": ["-m", "128M"],
    }

    for storage, source in (("installed", "source:saved"), ("archive", archive)):
        for mode in ("eager", "forked"):
            flags = ["--forked"] if mode == "forked" else []
            for case, options in cases.items():
                name = f"{storage}-{mode}-{case}"
                names.append(name)
                rejected = case not in ("absent", "matching")
                result = run(name, "restore", source, "--name", name,
                             *flags, *options, fail=rejected)
                if rejected:
                    assert "captured CPU and memory geometry" in result.stderr, result.stderr
                    run(name + "-no-row", "inspect", name, "--format", "json", fail=True)
                    assert not (home / "sandboxes" / name).exists(), name
                else:
                    verify_child(name)
                    run(name + "-stop", "stop", name)
            # A later valid restore must still work after the rejected attempts.
            name = f"{storage}-{mode}-recovery"
            names.append(name)
            run(name, "restore", source, "--name", name, *flags)
            verify_child(name)
            run(name + "-stop", "stop", name)

    # The guard is specific to resumed CPU/RAM, not disk-only fresh boots.
    names.append("disk-only")
    run("disk-only", "restore", "source:saved", "--name", "disk-only",
        "--disk-only", "--memory", "128M")
    verify_child("disk-only", ram=False, memory=128)
    assert hashlib.sha256((member / "snapshot.json").read_bytes()).hexdigest() == descriptor_hash
    verify_child("source")
    success = True
finally:
    # Only names created by this isolated test are eligible for cleanup.
    cleanup = []
    for name in reversed(names):
        try:
            result = subprocess.run([binary, "stop", name], env=env, input="", capture_output=True,
                                    text=True, timeout=30)
        except subprocess.TimeoutExpired as error:
            # A stuck stop must not skip other VMs or hide the original test failure.
            # TimeoutExpired may carry bytes even when text=True was requested.
            stderr = error.stderr or ""
            if isinstance(stderr, bytes):
                stderr = stderr.decode(errors="replace")
            cleanup.append({"name": name, "exit": "timeout", "timeout_seconds": error.timeout,
                            "stderr": stderr})
            continue
        except OSError as error:
            cleanup.append({"name": name, "exit": "error", "stderr": str(error)})
            continue
        cleanup.append({"name": name, "exit": result.returncode, "stderr": result.stderr})
    (root / "results.json").write_text(json.dumps(
        {"success": success, "layout": layout, "binary": binary, "rows": rows, "cleanup": cleanup}, indent=2))
