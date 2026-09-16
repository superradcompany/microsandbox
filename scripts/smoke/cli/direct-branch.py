#!/usr/bin/env python3
"""Opt-in direct branch invariants and release timing; stops every test VM."""

import json
import os
from pathlib import Path
import subprocess
import time

binary = os.environ["MSB_PATH"]
# Match CI's public mirror; callers may select an explicit local fixture instead.
image = os.environ.get("MSB_TEST_IMAGE", "mirror.gcr.io/library/alpine:latest")
root = Path(os.environ["STACK8_OUT"])
root.mkdir(parents=True, exist_ok=True)
prefix = os.environ.get("STACK8_PREFIX", f"branch8-{os.getpid()}")
layout = os.environ.get("STACK8_LAYOUT", "flat:512M")
rows = []
names = []


def run(label, *args, expected=0):
    started = time.perf_counter()
    result = subprocess.run([binary, *args], text=True, capture_output=True, timeout=120)
    elapsed = (time.perf_counter() - started) * 1000
    (root / f"{label}.stdout").write_text(result.stdout)
    (root / f"{label}.stderr").write_text(result.stderr)
    row = {"case": label, "ms": round(elapsed, 2), "exit": result.returncode}
    rows.append(row)
    print(json.dumps(row), flush=True)
    if expected is not None and result.returncode != expected:
        raise RuntimeError(f"{label}: {result.stderr[-4000:]}")
    return result


def exec_guest(name, script, label):
    return run(label, "exec", name, "--", "sh", "-c", script).stdout.strip()


def branch(source, child, label):
    names.append(child)
    run(label, "branch", source, "--name", child)
    assert exec_guest(child, "cat /dev/shm/branch-marker", label + "-ready") == "source"


def capture(source, member, label):
    result = run(label, "snapshot", "create", member, "--from-sandbox", source, "--full")
    # A member's bare alias no longer identifies its installed group; use the returned path.
    path = Path(result.stdout.strip().splitlines()[-1])
    assert (path / "snapshot.json").is_file(), path
    return str(path)


def benchmark(source):
    # One source and at most one measured child: do not let accumulating VMs distort later
    # samples. Each CLI return includes activation; first guest command is recorded separately.
    for i in range(10):
        if os.environ.get("STACK8_BENCH_COMPACT") == "1" and i > 1:
            run(f"setup-compact-branch-{i}", "modify", source, "--compact", "--format", "json")
        child = prefix + f"-bench-{i}"
        branch(source, child, f"branch-{i}")
        run(f"stop-branch-{i}", "stop", child)
    saved = prefix + "-warm"
    if os.environ.get("STACK8_BENCH_COMPACT") == "1":
        run("setup-compact-snapshot", "modify", source, "--compact", "--format", "json")
    saved_path = capture(source, saved, "capture-warm-source")
    for mode in ("forked", "eager"):
        for i in range(8):
            child = prefix + f"-{mode}-{i}"
            names.append(child)
            run(f"{mode}-restore-{i}", "create", "--name", child, "--from-snapshot", saved_path,
                *(["--forked"] if mode == "forked" else []))
            assert exec_guest(child, "cat /dev/shm/branch-marker", f"{mode}-ready-{i}") == "source"
            run(f"stop-{mode}-{i}", "stop", child)
    for i in range(5):
        if os.environ.get("STACK8_BENCH_COMPACT") == "1":
            run(f"setup-compact-pipeline-{i}", "modify", source, "--compact", "--format", "json")
        saved = prefix + f"-full-{i}"
        child = prefix + f"-durable-{i}"
        names.append(child)
        saved_path = capture(source, saved, f"pipeline-capture-{i}")
        run(f"pipeline-restore-{i}", "create", "--name", child, "--from-snapshot", saved_path, "--forked")
        assert exec_guest(child, "cat /dev/shm/branch-marker", f"pipeline-ready-{i}") == "source"
        run(f"stop-pipeline-{i}", "stop", child)


try:
    source = prefix + "-source"
    names.append(source)
    run("boot", "create", image, "--name", source, "--root-disk", layout,
        "--memory", "256M", "--cpus", "2")
    exec_guest(source, "echo source > /dev/shm/branch-marker; echo source > /disk-marker; sh -c 'i=0; while :; do i=$((i+1)); echo $i > /dev/shm/branch-counter; sleep 0.02; done' >/tmp/branch-counter.log 2>&1 </dev/null &", "prepare")
    if os.environ.get("STACK8_BENCH_ONLY") == "1":
        benchmark(source)
        raise SystemExit(0)
    before = set((Path(os.environ["MSB_HOME"]) / "snapshots").glob("*"))
    branch(source, prefix + "-first", "first-branch")
    for i in range(5):
        branch(source, prefix + f"-repeat-{i}", f"repeat-branch-{i}")
    after = set((Path(os.environ["MSB_HOME"]) / "snapshots").glob("*"))
    assert before == after, "direct branch installed a snapshot"
    for path in (Path(os.environ["MSB_HOME"]) / "sandboxes" / source / "runtime" / "checkpoint-store" / "objects").rglob("*"):
        if path.is_file():
            assert path.stat().st_size < 8 * 1024 * 1024, "direct branch emitted a large RAM object"
    refused = run("name-collision", "branch", source, "--name", prefix + "-first", expected=None)
    assert refused.returncode != 0
    child = prefix + "-first"
    exec_guest(child, "echo child > /dev/shm/branch-marker; echo child > /disk-marker", "mutate-child")
    assert exec_guest(source, "cat /dev/shm/branch-marker; cat /disk-marker", "source-isolation") == "source\nsource"
    assert exec_guest(prefix + "-repeat-0", "cat /dev/shm/branch-marker; cat /disk-marker", "sibling-isolation") == "source\nsource"
    # Branch a branch after private writes; capturing its original file would lose these writes.
    grandchild = prefix + "-grandchild"
    names.append(grandchild)
    run("branch-child", "branch", child, "--name", grandchild)
    assert exec_guest(grandchild, "cat /dev/shm/branch-marker; cat /disk-marker", "grandchild-private-writes") == "child\nchild"
    counter = int(exec_guest(grandchild, "cat /dev/shm/branch-counter", "counter-before"))
    time.sleep(0.1)
    assert int(exec_guest(grandchild, "cat /dev/shm/branch-counter", "counter-after")) > counter
    run("pause-source", "pause", source)
    branch(source, prefix + "-paused", "paused-branch")
    rejected = run("source-still-paused", "exec", source, "--", "true", expected=None)
    assert rejected.returncode != 0
    run("resume-source", "resume", source)
    # Compare durable capture+forked-child against the same source and readiness endpoint.
    for i in range(3):
        snap = prefix + f"-saved-{i}"
        snap_path = capture(source, snap, f"full-capture-{i}")
        name = prefix + f"-restored-{i}"
        names.append(name)
        run(f"forked-restore-{i}", "create", "--name", name, "--from-snapshot", snap_path, "--forked")
        assert exec_guest(name, "cat /dev/shm/branch-marker", f"restore-ready-{i}") == "source"
    if os.environ.get("STACK8_MAINTENANCE") == "1" and not layout.startswith("tmpfs"):
        run("grow-source", "modify", source, "--root-disk", "768M", "--format", "json")
        run("compact-source", "modify", source, "--compact", "--format", "json")
        branch(source, prefix + "-after-grow", "branch-after-grow")
    run("stop-source", "stop", source)
    run("stop-child", "stop", child)
    assert exec_guest(grandchild, "cat /dev/shm/branch-marker; cat /disk-marker", "survives-source-stop") == "child\nchild"
finally:
    for name in reversed(names):
        run("cleanup-" + name, "stop", name, expected=None)
    (root / "results.json").write_text(json.dumps(rows, indent=2))
