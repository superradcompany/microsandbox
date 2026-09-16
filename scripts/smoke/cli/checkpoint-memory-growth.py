#!/usr/bin/env python3
"""Live grown-RAM checkpoint regression on macOS or Linux.

Usage: python3 checkpoint-memory-growth.py MSB_BIN MATCHING_AGENTD LIBKRUNFW
Creates a disposable MSB_HOME under /tmp and retains JSON evidence. The fixture
uses 384 MiB of random tmpfs data so the original 256 MiB boot RAM cannot hold it.
Set CBH_ROOT_DISK=flat:512M to exercise a flat root instead of the layered default.
Each test sandbox is force-stopped in finally; unrelated sandboxes are untouched.
"""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

binary, agent, firmware = sys.argv[1:4]
root = Path(tempfile.mkdtemp(prefix="cbh-", dir="/tmp"))
env = dict(os.environ, MSB_HOME=str(root / "home"), MSB_AGENTD_PATH=agent,
           MSB_LIBKRUNFW_PATH=firmware, MSB_PATH=binary)
names = []
results = []
print(f"Evidence: {root}", flush=True)

def run(*args, timeout=240, check=True):
    start = time.monotonic()
    result = subprocess.run([binary, *args], env=env, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    record = dict(args=args, seconds=time.monotonic()-start, code=result.returncode,
                  stdout=result.stdout, stderr=result.stderr)
    results.append(record)
    (root / "results.json").write_text(json.dumps(results, indent=2))
    print(json.dumps(record), flush=True)
    if check and result.returncode:
        raise RuntimeError(f"command failed: {args}")
    return result.stdout

try:
    names.append("source")
    run("create", "alpine", "--name", "source", "--memory", "256M",
        "--max-memory", "1G", "--cpus", "1", "--max-cpus", "2",
        "--root-disk", os.environ.get("CBH_ROOT_DISK", "512M"), "--tmpfs", "/work:640M")
    run("modify", "source", "--memory", "768M", "--cpus", "2", "--format", "json")
    run("exec", "source", "--", "sh", "-ec",
        "dd if=/dev/urandom of=/work/payload bs=1M count=384; sha256sum /work/payload > /work/hash; grep MemTotal /proc/meminfo; cat /sys/devices/system/cpu/online")
    run("snapshot", "create", "grown", "--group", "checks", "--from-sandbox", "source", "--full")
    for child, forked in [("eager", False), ("forked", True)]:
        names.append(child)
        run("create", "--name", child, "--from-snapshot", "checks:grown", *(["--forked"] if forked else []))
        run("exec", child, "--", "sh", "-ec", "sha256sum -c /work/hash; grep MemTotal /proc/meminfo; cat /sys/devices/system/cpu/online")
        run("modify", child, "--memory", "1G", "--cpus", "1", "--format", "json")
        run("exec", child, "--", "sh", "-ec", "sha256sum -c /work/hash; grep MemTotal /proc/meminfo; for i in 1 2 3 4 5; do test \"$(cat /sys/devices/system/cpu/online)\" = 0 && exit 0; sleep 1; done; cat /sys/devices/system/cpu/online; exit 1")
    names.append("branch")
    run("branch", "source", "--name", "branch")
    run("exec", "branch", "--", "sha256sum", "-c", "/work/hash")
finally:
    for name in reversed(names):
        try:
            run("stop", "--force", name, check=False, timeout=30)
        except Exception as error:
            print(f"Cleanup needs attention for {name}: {error}", flush=True)
    print(f"Evidence retained: {root}", flush=True)

