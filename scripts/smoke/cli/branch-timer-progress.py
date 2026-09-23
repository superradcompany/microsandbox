#!/usr/bin/env python3
"""Repeated branching with retained siblings and a timer-driven guest workload.

Use an isolated MSB_HOME, matching MSB_PATH/MSB_LIBKRUNFW_PATH, and unique
STACK8_PREFIX/STACK8_OUT. STACK8_REPEATS defaults to 100 and STACK8_RETAIN to 8.
Retained immutable RAM cache entries need disk space even after VMs stop.
"""
import json
import os
from pathlib import Path
import subprocess
import time

binary = os.environ["MSB_PATH"]
out = Path(os.environ["STACK8_OUT"])
out.mkdir(parents=True, exist_ok=True)
prefix = os.environ["STACK8_PREFIX"]
repeats = int(os.environ.get("STACK8_REPEATS", "100"))
retain = int(os.environ.get("STACK8_RETAIN", "8"))
assert repeats > 0 and retain > 0
source = prefix + "-source"
names = [source]
live_children = []
rows = []


def run(label, *args, check=True):
    start = time.monotonic()
    try:
        result = subprocess.run([binary, *args], capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        rows.append({"case": label, "exit": "timeout"})
        raise
    row = {"case": label, "exit": result.returncode,
           "ms": round((time.monotonic() - start) * 1000, 2)}
    rows.append(row)
    (out / (label + ".stdout")).write_text(result.stdout)
    (out / (label + ".stderr")).write_text(result.stderr)
    if check:
        assert result.returncode == 0, (row, result.stderr)
    return result.stdout.strip()


try:
    run("create", "create", "alpine", "--name", source, "--root-disk", "tmpfs:128M",
        "--memory", "256M", "--cpus", "2")
    # Atomic replacement prevents a concurrent reader mistaking a truncated
    # counter file for a stalled timer. A background process survives exec exit.
    run("prepare", "exec", source, "--", "sh", "-c",
        "sh -c 'i=0; while :; do i=$((i+1)); echo $i > /dev/shm/count.next; "
        "mv /dev/shm/count.next /dev/shm/count; sleep 0.02; done' "
        ">/tmp/counter.log 2>&1 </dev/null &")
    run("ready", "exec", source, "--", "sh", "-c",
        "while [ ! -s /dev/shm/count ]; do sleep 0.02; done")
    for index in range(repeats):
        child = prefix + "-" + str(index)
        names.append(child)
        run("branch-" + str(index), "branch", source, "--name", child)
        first = int(run("read-" + str(index), "exec", child, "--", "cat", "/dev/shm/count"))
        run("progress-" + str(index), "exec", child, "--", "sh", "-c",
            "n=" + str(first) + "; for i in $(seq 1 100); do "
            '[ "$(cat /dev/shm/count)" -gt "$n" ] && exit 0; sleep 0.02; done; exit 1')
        live_children.append(child)
        if len(live_children) > retain:
            run("retire-" + str(index), "stop", live_children.pop(0))
        print(json.dumps({"branch": index, "timer_progress": "pass"}), flush=True)
finally:
    # Failed creation must not be followed by exec/start: that would test an
    # unintended cold boot instead of the failed restore. Stop is always safe.
    for name in reversed(names):
        try:
            run("cleanup-" + name, "stop", name, check=False)
        except Exception as error:
            rows.append({"case": "cleanup-" + name, "error": str(error)})
    (out / "results.json").write_text(json.dumps(rows, indent=2))
