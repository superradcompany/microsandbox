#!/usr/bin/env python3
"""Late restore failure must preserve sealed bytes and refuse cold-boot paths.

Run only with an isolated MSB_HOME: this temporarily blocks its memory cache.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

assert os.environ.get("MSB_TEST_DISPOSABLE_HOME") == "1", "requires an isolated test home"
binary = os.environ["MSB_PATH"]
home = Path(os.environ["MSB_HOME"])
out = Path(os.environ["STACK8_OUT"])
out.mkdir(parents=True, exist_ok=True)
prefix = os.environ.get("STACK8_PREFIX", "failed-restore-" + str(os.getpid()))
source, child, healthy = (prefix + suffix for suffix in ("-source", "-failed", "-healthy"))
snapshot = prefix + "-saved"
cache = home / "cache" / "memory"
held = cache.with_name("memory-held-" + prefix)
rows = []

def call(label, *args, expected=0):
    start = time.monotonic()
    result = subprocess.run([binary, *args], capture_output=True, text=True, timeout=120)
    rows.append(dict(case=label, exit=result.returncode, ms=(time.monotonic()-start)*1000,
                     stdout=result.stdout, stderr=result.stderr))
    if expected is not None:
        assert result.returncode == expected, rows[-1]
    return result

def layers():
    root = home / "snapshots" / snapshot
    paths = sorted(p for p in root.rglob('*') if p.is_file() and p.suffix in ('.raw', '.qcow2', '.ext4'))
    assert paths, "fixture must include sealed disk bytes"
    result = {}
    for path in paths:
        with path.open('rb') as file:
            digest = hashlib.sha256()
            for chunk in iter(lambda: file.read(1024 * 1024), b''):
                digest.update(chunk)
            result[str(path.relative_to(root))] = digest.hexdigest()
    return result

blocked = False
try:
    call("source", "create", "alpine", "--name", source, "--root-disk", os.environ.get("STACK8_LAYOUT", "flat:512M"), "--memory", "256M")
    call("marker", "exec", source, "--", "sh", "-c", "echo preserved > /dev/shm/restore-marker; echo disk-preserved > /restore-disk-marker")
    call("capture", "snapshot", "create", snapshot, "--from-sandbox", source, "--full")
    before = layers()
    # Trigger a real host I/O error during memory installation, after child staging
    # and DB insertion. No production test-only failure hook is necessary.
    assert not held.exists()
    if cache.exists():
        cache.rename(held)
    cache.write_bytes(b"intentional isolated test obstruction")
    blocked = True
    failure = call("restore-fails", "create", "--name", child, "--from-snapshot", snapshot, "--forked", expected=None)
    assert failure.returncode != 0
    call("failed-row-exists", "inspect", child)
    cache.unlink()
    blocked = False
    if held.exists():
        held.rename(cache)
    for label, args in [("start", ["start", child]), ("exec", ["exec", child, "--", "true"]),
                        ("modify", ["modify", child, "--root-disk", "8G"]),
                        ("compact", ["modify", child, "--compact"]),
                        ("snapshot", ["snapshot", "create", prefix+'-invalid', "--from-sandbox", child])]:
        refused = call(label + "-refused", *args, expected=None)
        assert refused.returncode != 0 and "incomplete restore" in refused.stderr, rows[-1]
    assert layers() == before, "failed restore or later lifecycle mutated sealed disk bytes"
    call("healthy-restore", "create", "--name", healthy, "--from-snapshot", snapshot, "--forked")
    assert call("healthy-marker", "exec", healthy, "--", "cat", "/dev/shm/restore-marker").stdout.strip() == "preserved"
    call("healthy-stop", "stop", healthy)
    call("healthy-later-start", "start", healthy)
    assert call("healthy-disk-marker", "exec", healthy, "--", "cat", "/restore-disk-marker").stdout.strip() == "disk-preserved"
    assert layers() == before, "ordinary later startup mutated the original sealed snapshot"
    print(json.dumps({"late_failure": "pass", "start_exec_modify_compact_snapshot_refused": "pass", "sealed_bytes": "unchanged", "fresh_restore_and_later_start": "pass"}))
finally:
    if blocked:
        cache.unlink()
    if held.exists():
        held.rename(cache)
    for name in (healthy, child, source):
        call("cleanup-" + name, "stop", name, expected=None)
    (out / "results.json").write_text(json.dumps(rows, indent=2))
