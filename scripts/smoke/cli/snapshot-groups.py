#!/usr/bin/env python3
"""Opt-in live snapshot-group qualification in an isolated MSB_HOME.

Set MSB_PATH and GROUP_TEST_OUT; optionally GROUP_TEST_LAYOUT=512M, flat:512M, or tmpfs:128M.
All created VMs are stopped in finally, and every command/timing is retained.
"""

from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess
import time

binary = os.environ["MSB_PATH"]
# Match CI's public mirror; callers may select an explicit local fixture instead.
image = os.environ.get("MSB_TEST_IMAGE", "mirror.gcr.io/library/alpine:latest")
root = Path(os.environ["GROUP_TEST_OUT"])
root.mkdir(parents=True, exist_ok=False)
home = root / "home"
env = dict(os.environ, MSB_HOME=str(home))
layout = os.environ.get("GROUP_TEST_LAYOUT", "flat:512M")
full_only = layout.startswith("tmpfs:")
rows = []
names = []


def run(label, *args, fail=False):
    started = time.perf_counter()
    result = subprocess.run([binary, *map(str, args)], env=env, capture_output=True,
                            text=True, timeout=180)
    row = {"case": label, "ms": round((time.perf_counter() - started) * 1000, 2),
           "exit": result.returncode}
    rows.append(row)
    print(json.dumps(row), flush=True)
    (root / f"{label}.stdout").write_text(result.stdout)
    (root / f"{label}.stderr").write_text(result.stderr)
    if (result.returncode != 0) != fail:
        raise RuntimeError(f"{label}: {result.stderr[-3000:]}")
    return result.stdout.strip()


def guest(label, name, script):
    return run(label, "exec", name, "--", "sh", "-ec", script)


def create(name, snapshot=None, forked=False):
    names.append(name)
    args = ["create", "--name", name]
    if snapshot:
        args += ["--from-snapshot", snapshot]
    else:
        args += [image, "--root-disk", layout, "--memory", "256M", "--cpus", "2"]
    if forked:
        args.append("--forked")
    run("create-" + name, *args)


def capture(label, source, member, group="work", full=False, fail=False):
    args = ["snapshot", "create", member, "--from-sandbox", source, "--group", group]
    if full or full_only:
        args.append("--full")
    output = run(label, *args, fail=fail)
    if fail:
        return None
    path = Path(output.splitlines()[-1])
    descriptor = json.loads((path / "snapshot.json").read_text())
    assert path.parent == home / "snapshots" / group, path
    assert path.name == descriptor["snapshot_id"], path
    return path, descriptor


def head(label, selector):
    return json.loads(run(label, "snapshot", "head", selector, "--format", "json"))


try:
    create("source")
    guest("source-one", "source", "echo one > /disk-marker; echo ram-one > /dev/shm/marker; sync")
    cp1, d1 = capture("capture-cp1", "source", "cp1")
    assert d1["parent"] is None
    assert head("initial-head", "work")["head"] == d1["snapshot_id"]
    guest("source-two", "source", "echo two > /disk-marker; sync")
    cp2, d2 = capture("capture-cp2", "source", "cp2")
    assert d2["parent"] == d1["snapshot_id"]
    assert head("advanced-head", "work")["head"] == d2["snapshot_id"]

    create("old-child", "work:cp1")
    assert guest("read-old-child", "old-child", "cat /disk-marker") == "one"
    branch, db = capture("capture-old-child", "old-child", "experiment")
    assert db["parent"] == d1["snapshot_id"]
    assert head("sibling-keeps-head", "work")["head"] == d2["snapshot_id"]
    assert head("select-sibling", "work:experiment")["head"] == db["snapshot_id"]
    create("selected-child", "work")
    assert guest("read-selected-head", "selected-child", "cat /disk-marker") == "one"
    run("stop-selected-child", "stop", "selected-child")
    head("select-cp2", "work:cp2")

    # Same source serialization creates ancestry; different children of one head are siblings.
    create("race-a", "work:cp2")
    create("race-b", "work:cp2")
    with ThreadPoolExecutor(max_workers=2) as pool:
        pending = [pool.submit(capture, "capture-" + child, child, child)
                   for child in ("race-a", "race-b")]
        siblings = [future.result() for future in pending]
    ids = {desc["snapshot_id"] for _, desc in siblings}
    assert all(desc["parent"] == d2["snapshot_id"] for _, desc in siblings)
    assert head("race-head", "work")["head"] in ids
    assert all(path.exists() for path, _ in siblings)
    for name in ("old-child", "race-a", "race-b"):
        run("stop-" + name, "stop", name)
    head("select-cp2-again", "work:cp2")

    # Full capture, direct local branch ancestry, and paused-source preservation.
    full1, f1 = capture("capture-full1", "source", "full1", full=True)
    assert f1["parent"] == d2["snapshot_id"]
    names.append("local-child")
    run("local-branch", "branch", "source", "--name", "local-child")
    local_snap, dl = capture("capture-local-child", "local-child", "local-child", full=True)
    assert dl["parent"] == f1["snapshot_id"]
    guest("source-three", "source", "echo three > /disk-marker; echo ram-three > /dev/shm/marker; sync")
    run("pause-source", "pause", "source")
    full2, f2 = capture("capture-paused-full2", "source", "full2", full=True)
    assert f2["parent"] == f1["snapshot_id"]
    run("resume-source", "resume", "source")
    assert guest("source-still-live", "source", "cat /disk-marker") == "three"
    run("stop-local-child", "stop", "local-child")

    # A rejected alias collision cannot replace the artifact or advance the cursor/head.
    before = (full2 / "snapshot.json").read_bytes()
    current = head("head-before-conflict", "work")["head"]
    capture("duplicate-name-refused", "source", "full2", fail=True)
    assert (full2 / "snapshot.json").read_bytes() == before
    assert head("head-after-conflict", "work")["head"] == current
    full3, f3 = capture("capture-after-conflict", "source", "full3", full=True)
    assert f3["parent"] == f2["snapshot_id"]

    base_archive = root / "base.msb"
    delta_archive = root / "delta.msb"
    run("export-base", "snapshot", "save", full1, base_archive)
    run("export-delta", "snapshot", "save", full2, delta_archive, "--since", full1)
    inventory = json.loads(subprocess.check_output(["tar", "-xOf", str(delta_archive), "archive.json"]))
    dependent = inventory["completeness"] == "dependent"
    # A RAM-only cut can have no reusable objects: --since then emits a standalone archive.
    # Require a base exactly when the archive actually omitted required payloads.
    run("missing-base" + ("-refused" if dependent else "-not-needed"), "snapshot", "load",
        delta_archive, "--group", "missing", fail=dependent)
    if dependent:
        assert not (home / "snapshots" / "missing").exists()
    imported_base = Path(run("import-base", "snapshot", "load", base_archive,
                             "--group", "received").splitlines()[-1])
    imported_delta = Path(run("import-delta", "snapshot", "load", delta_archive,
                              "--group", "received", "--base", "received:full1").splitlines()[-1])
    assert imported_base.name == f1["snapshot_id"] and imported_delta.name == f2["snapshot_id"]
    assert head("import-advanced-head", "received")["head"] == f2["snapshot_id"]
    run("reimport-old", "snapshot", "load", base_archive, "--group", "received")
    assert head("old-import-kept-head", "received")["head"] == f2["snapshot_id"]
    run("reimport-set-head", "snapshot", "load", base_archive, "--group", "received", "--set-head")
    assert head("old-import-explicit-head", "received")["head"] == f1["snapshot_id"]
    run("head-removal-refused", "snapshot", "remove", "received:full1", "--force", fail=True)

    duplicate = Path(run("import-second-group", "snapshot", "load", base_archive).splitlines()[-1])
    assert duplicate.name == imported_base.name and duplicate.parent != imported_base.parent
    run("ambiguous-id-refused", "snapshot", "inspect", f1["snapshot_id"], fail=True)
    run("reindex", "snapshot", "reindex")
    for mode in ("eager", "forked"):
        child = "restored-" + mode
        create(child, "received:full2", forked=mode == "forked")
        assert guest("restored-state-" + mode, child,
                     "cat /disk-marker; cat /dev/shm/marker") == "three\nram-three"
        run("stop-" + child, "stop", child)

    # Direct archive capture records ancestry but never creates an installed member.
    before_members = sorted(str(p) for p in (home / "snapshots").rglob("snapshot.json"))
    direct = root / "direct.msb"
    run("direct-capture", "snapshot", "create", "direct", "--from-sandbox", "source", "--full", "--output", direct)
    assert sorted(str(p) for p in (home / "snapshots").rglob("snapshot.json")) == before_members
    create("direct-restored", str(direct), forked=True)
    assert guest("direct-restored-state", "direct-restored", "cat /dev/shm/marker") == "ram-three"
    assert sorted(str(p) for p in (home / "snapshots").rglob("snapshot.json")) == before_members
    run("stop-direct-restored", "stop", "direct-restored")
    run("stop-source", "stop", "source")
    if full_only:
        capture("stopped-tmpfs-refused", "source", "stopped", fail=True)
    else:
        stopped, stopped_desc = capture("stopped-capture", "source", "stopped")
        assert stopped_desc["parent"] != f3["snapshot_id"], "direct archive did not advance source ancestry"
        create("stopped-restored", "work:stopped")
        assert guest("stopped-restored-state", "stopped-restored", "cat /disk-marker") == "three"
    print(json.dumps({"pass": True, "layout": layout, "commands": len(rows)}), flush=True)
finally:
    for name in reversed(names):
        result = subprocess.run([binary, "stop", name], env=env, capture_output=True,
                                text=True, timeout=30)
        (root / ("cleanup-" + name + ".log")).write_text(result.stdout + result.stderr)
    (root / "results.json").write_text(json.dumps(rows, indent=2))
