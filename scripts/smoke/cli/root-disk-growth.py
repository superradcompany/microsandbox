#!/usr/bin/env python3
"""Live root-growth matrix. Requires an isolated MSB_HOME and matching MSB_BIN/firmware."""

import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import time


binary = os.environ["MSB_BIN"]
home = Path(os.environ["MSB_HOME"])
report = Path(os.environ["QUAL_ROOT"])
report.mkdir(parents=True, exist_ok=True)
names = []
results = []


def run(label, *args, refuse=False):
    started = time.perf_counter()
    result = subprocess.run([binary, *args], text=True, capture_output=True, timeout=180)
    elapsed = (time.perf_counter() - started) * 1000
    (report / f"{label}.stdout").write_text(result.stdout)
    (report / f"{label}.stderr").write_text(result.stderr)
    passed = result.returncode != 0 if refuse else result.returncode == 0
    results.append({"case": label, "passed": passed, "elapsed_ms": elapsed})
    (report / "results.json").write_text(json.dumps(results, indent=2))
    print(f"{label}: {'PASS' if passed else 'FAIL'} {elapsed:.2f} ms", flush=True)
    if not passed:
        raise AssertionError(result.stdout + result.stderr)
    return result.stdout


def guest(label, name, script):
    return run(label, "exec", name, "--", "sh", "-c", script)


def phase_grow(label, name, mib):
    # The runtime response separates the short VM pause from online ext4 expansion.
    # Follow with the SDK-backed CLI call to reconcile/persist its desired configuration.
    if os.name != "nt":
        digest = hashlib.sha256(name.encode()).hexdigest()[:24]
        path = home / "run" / "sandboxes" / digest / "control.sock"
        with socket.socket(socket.AF_UNIX) as connection:
            connection.settimeout(180)
            connection.connect(str(path))
            connection.sendall(json.dumps({"op": "root_disk_grow", "size_bytes": mib * 1048576}).encode() + b"\n")
            with connection.makefile("rb") as reader:
                reply = json.loads(reader.readline())
        (report / f"{label}.phases.json").write_text(json.dumps(reply, indent=2))
        assert reply["ok"], reply
        assert reply["root_disk"]["filesystem_bytes"] == mib * 1048576
    run(label, "modify", name, "--root-disk", f"{mib}M", "--format", "json")


def journal(name):
    return json.loads((home / "sandboxes" / name / "runtime" / "root-disk.json").read_text())


def file_hash(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


try:
    for layout in ("managed", "flat"):
        name = f"{os.environ.get('QUAL_PREFIX', 'grow')}-{layout}"
        names.append(name)
        disk = "512M" if layout == "managed" else "flat:512M"
        run(f"{layout}-create", "create", "-n", name, "--root-disk", disk, "-m", "256M", "--max-duration", "20m", "alpine")
        guest(f"{layout}-seed", name, "dd if=/dev/urandom of=/payload bs=1048576 count=8 2>/dev/null; sha256sum /payload >/expected; echo ram >/dev/shm/grow-marker; sync")
        phase_grow(f"{layout}-raw-live", name, 768)
        guest(f"{layout}-new-space", name, "dd if=/dev/zero of=/space bs=1048576 count=600 conv=fsync && test $(stat -c %s /space) = 629145600 && rm /space && sha256sum -c /expected")
        run(f"{layout}-old-snapshot", "snapshot", "create", f"{name}-old", "--from-sandbox", name, "--full")
        before = journal(name)
        ancestor = Path(before["layers"][0]["path"])
        ancestor_before = file_hash(ancestor)
        phase_grow(f"{layout}-qcow-live", name, 1024)
        phase_grow(f"{layout}-qcow-repeat", name, 1280)
        assert len(journal(name)["layers"]) == len(before["layers"])
        assert file_hash(ancestor) == ancestor_before
        run(f"{layout}-shrink-refused", "modify", name, "--root-disk", "512M", refuse=True)
        run(f"{layout}-new-snapshot", "snapshot", "create", f"{name}-new", "--from-sandbox", name, "--full")
        run(f"{layout}-compact", "modify", name, "--compact", "--format", "json")
        phase_grow(f"{layout}-compacted-live", name, 1536)
        phase_grow(f"{layout}-partial-group-live", name, 1700)
        run(f"{layout}-stop", "stop", name)
        run(f"{layout}-stopped-grow", "modify", name, "--root-disk", "1792M", "--format", "json")
        run(f"{layout}-start", "start", name)
        guest(f"{layout}-after-stopped-grow", name, "sha256sum -c /expected; df -k /")
        run(f"{layout}-defer", "modify", name, "--root-disk", "2G", "--next-start", "--format", "json")
        run(f"{layout}-defer-stop", "stop", name)
        run(f"{layout}-defer-start", "start", name)
        guest(f"{layout}-defer-space", name, "dd if=/dev/zero of=/space bs=1048576 count=1800 conv=fsync && rm /space && sha256sum -c /expected")
        run(f"{layout}-final-stop", "stop", name)
        run(f"{layout}-stopped-snapshot", "snapshot", "create", f"{name}-stopped", "--from-sandbox", name, "--integrity")
        run(f"{layout}-verify", "snapshot", "verify", f"{name}-stopped")
        for suffix, capacity in (("old", 768), ("new", 1280)):
            child = f"{name}-{suffix}-child"
            names.append(child)
            run(f"{layout}-{suffix}-restore", "create", "-n", child, "--from-snapshot", f"{name}-{suffix}")
            guest(f"{layout}-{suffix}-restored-data", child, "sha256sum -c /expected && test $(cat /dev/shm/grow-marker) = ram")
            # Full restore retains captured block capacity, not the source's later size.
            layers = journal(child)["layers"]
            head = Path(layers[-1]["path"])
            with head.open("rb") as file:
                file.seek(24)
                assert int.from_bytes(file.read(8), "big") == capacity * 1048576
            run(f"{layout}-{suffix}-child-stop", "stop", child)
    print(f"Root-growth matrix passed: {report / 'results.json'}", flush=True)
finally:
    for name in names:
        subprocess.run([binary, "stop", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
