#!/usr/bin/env python3
"""Live extra-disk checkpoint isolation and portable-archive regression.

Usage: checkpoint-managed-volumes.py MSB_BIN MATCHING_AGENTD LIBKRUNFW
Set CBH_ROOT_DISK=flat:512M to repeat with a flat root. Uses two disposable
managed volumes and an isolated home; no existing sandbox or volume is touched.
"""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

binary, agent, firmware = sys.argv[1:4]
binary, agent, firmware = (str(Path(path).resolve()) for path in (binary, agent, firmware))
root = Path(tempfile.mkdtemp(prefix="cbh-volumes-", dir=os.environ.get("CBH_TEST_ROOT")))
env = dict(os.environ, MSB_HOME=str(root / "home"), MSB_AGENTD_PATH=agent,
           MSB_LIBKRUNFW_PATH=firmware, MSB_PATH=binary)
names = []
results = []
print(f"Evidence: {root}", flush=True)


def run(*args, timeout=240, check=True, environment=None):
    started = time.monotonic()
    output = subprocess.run([binary, *args], env=environment or env, capture_output=True,
                            text=True, timeout=timeout)
    result = dict(args=args, home=(environment or env)["MSB_HOME"], seconds=time.monotonic() - started,
                  code=output.returncode, stdout=output.stdout, stderr=output.stderr)
    results.append(result)
    (root / "results.json").write_text(json.dumps(results, indent=2))
    print(json.dumps(result), flush=True)
    if check and output.returncode:
        raise RuntimeError(f"command failed: {args}")
    return output


def create(name, *args, environment=None):
    names.append((name, environment))
    return run("create", "--name", name, *args, environment=environment)


def verify(name, generation, environment=None):
    run("exec", name, "--", "sh", "-ec",
        f"test \"$(cat /data/generation)\" = {generation}; "
        f"test \"$(cat /other/generation)\" = {generation}; "
        "sha256sum -c /data/checksum; sha256sum -c /other/checksum", environment=environment)


def stop_remove(name, environment=None):
    # Exercise graceful completion before removal; force is only failure-path cleanup.
    run("stop", name, environment=environment)
    run("remove", name, environment=environment)
    names.remove((name, environment))


try:
    for volume in ["data", "other"]:
        run("volume", "create", volume, "--kind", "disk", "--size", "128M")
    create("source", "alpine", "--memory", "512M", "--max-memory", "2G",
           "--root-disk", os.environ.get("CBH_ROOT_DISK", "512M"),
           "--mount-named", "data:/data:kind=disk,size=128M",
           "--mount-named", "other:/other:kind=disk,size=128M")
    run("exec", "source", "--", "sh", "-ec",
        "for dir in /data /other; do dd if=/dev/urandom of=$dir/payload bs=1M count=8; "
        "sha256sum $dir/payload > $dir/checksum; echo 1 > $dir/generation; done")
    run("snapshot", "create", "one", "--group", "volumes", "--from-sandbox", "source", "--full")
    verify("source", 1)
    for child, forked in [("eager", False), ("forked", True)]:
        create(child, "--from-snapshot", "volumes:one", *(["--forked"] if forked else []))
        verify(child, 1)
        run("exec", child, "--", "sh", "-ec", "echo child > /data/generation; echo child > /other/generation; sync")
        verify("source", 1)
        stop_remove(child)
    # Full restore above preserves dirty guest cache. A disk-only cold boot intentionally
    # discards that RAM, so establish persisted checksums before testing its crash-consistent view.
    run("exec", "source", "--", "sh", "-ec", "echo 2 > /data/generation; echo 2 > /other/generation; sync")
    run("snapshot", "create", "two", "--group", "volumes", "--from-sandbox", "source", "--full")
    verify("source", 2)
    run("snapshot", "save", "volumes:one", str(root / "one.msb"), "--with-image")
    run("snapshot", "save", "volumes:two", str(root / "two.msb"), "--since", "volumes:one")
    # A fresh home and pull=never prove the baseline archive includes everything needed
    # offline, rather than accidentally reusing the source's image/materialization cache.
    offline = dict(env, MSB_HOME=str(root / "offline-home"))
    run("snapshot", "load", str(root / "two.msb"), str(root / "one.msb"), "--group", "loaded", environment=offline)
    create("imported", "--from-snapshot", "loaded", "--forked", "--pull", "never", environment=offline)
    verify("imported", 2, environment=offline)
    create("disk-only", "--from-snapshot", "volumes:two", "--disk-only")
    verify("disk-only", 2)
    stop_remove("disk-only")
    # Direct full export must include both extra disks without installing another member.
    installed_before = sorted(str(p) for p in (root / "home" / "snapshots").rglob("snapshot.json"))
    direct = root / "direct.msb"
    run("snapshot", "create", "direct", "--from-sandbox", "source", "--full", "-o", str(direct))
    assert sorted(str(p) for p in (root / "home" / "snapshots").rglob("snapshot.json")) == installed_before
    create("direct", "--from-snapshot", str(direct), "--forked")
    verify("direct", 2)
    stop_remove("direct")
    names.append(("branch", None))
    run("branch", "source", "--name", "branch")
    verify("branch", 2)
    run("exec", "branch", "--", "sh", "-ec", "echo 3 > /data/generation; echo 3 > /other/generation")
    names.append(("grandchild", None))
    run("branch", "branch", "--name", "grandchild")
    verify("grandchild", 3)
    verify("source", 2)
    # Capturing and branching must retain the caller's existing pause.
    run("pause", "source")
    run("snapshot", "create", "paused", "--group", "volumes", "--from-sandbox", "source", "--full")
    assert json.loads(run("inspect", "source", "--format", "json").stdout)["status"] == "Paused"
    run("resume", "source")
    verify("source", 2)
    for name, environment in list(reversed(names)):
        stop_remove(name, environment)
    for environment in (env, offline):
        assert json.loads(run("list", "--format", "json", environment=environment).stdout) == []
    print("PASS: managed volumes, eager/forked, deltas, direct archive, disk-only, nested branch, paused capture, Stop/Remove", flush=True)
finally:
    for name, environment in reversed(names):
        try:
            run("stop", "--force", name, check=False, timeout=30, environment=environment)
            run("remove", name, check=False, timeout=30, environment=environment)
        except Exception as error:
            print(f"Cleanup needs attention for {name}: {error}", flush=True)
    print(f"Evidence retained: {root}", flush=True)
