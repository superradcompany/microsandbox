#!/usr/bin/env python3
"""Regression for Linux bounded WRITE_ZEROES on fresh Ubuntu managed roots.

Usage: python3 bounded-root-grow.py MSB_BIN MATCHING_AGENTD LIBKRUNFW
Uses a disposable home, preserves JSON evidence, and stops its own VM in finally.
Does not disable or override the runtime's default writeback limiter.
"""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

binary, agent, firmware = sys.argv[1:4]
root = Path(tempfile.mkdtemp(prefix="cbg-", dir="/tmp"))
env = dict(os.environ, MSB_HOME=str(root / "home"), MSB_AGENTD_PATH=agent,
           MSB_LIBKRUNFW_PATH=firmware, MSB_PATH=binary)
results = []
print(f"Evidence: {root}", flush=True)


def run(*args, check=True):
    started = time.monotonic()
    result = subprocess.run([binary, *args], env=env, text=True,
                            capture_output=True, timeout=240)
    record = dict(args=args, seconds=time.monotonic()-started, code=result.returncode,
                  stdout=result.stdout, stderr=result.stderr)
    results.append(record)
    (root / "results.json").write_text(json.dumps(results, indent=2))
    print(json.dumps(record), flush=True)
    if check and result.returncode:
        raise RuntimeError(f"command failed: {args}")
    return result.stdout


try:
    run("create", "ubuntu:24.04", "--name", "grow", "--memory", "512M",
        "--root-disk", "10G")
    run("exec", "grow", "--", "sh", "-ec",
        "dd if=/dev/urandom of=/root/grow-marker bs=1M count=32; "
        "sha256sum /root/grow-marker > /root/grow-hash; sync; df -B1 /")
    for size in (12, 14):
        plan = json.loads(run("modify", "grow", "--root-disk", f"{size}G", "--format", "json"))
        assert plan["applied"], plan
        # A successful CLI response must mean guest filesystem capacity, not only block capacity.
        run("exec", "grow", "--", "sh", "-ec",
            "sha256sum -c /root/grow-hash; "
            f"test $(df -B1 --output=size / | tail -n 1) -gt {(size-1)*1024**3}; "
            "df -B1 /; dmesg | tail -n 25")
        # The public grow-only API rejects an already-completed equal target. This differs
        # from retrying a pending filesystem expansion after a partially failed operation.
        repeat = json.loads(run("modify", "grow", "--root-disk", f"{size}G", "--format", "json", check=False))
        assert not repeat["applied"] and not repeat["changes"], repeat
        assert any("already" in item["message"] for item in repeat["conflicts"]), repeat
finally:
    run("stop", "--force", "grow", check=False)
    print(f"Evidence retained: {root}", flush=True)
