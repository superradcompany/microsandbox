#!/usr/bin/env python3
"""Opt-in live snapshot-group qualification in an isolated MSB_HOME.

Set MSB_PATH and GROUP_TEST_OUT; optionally GROUP_TEST_LAYOUT=512M, flat:512M, or tmpfs:128M.
All created VMs are stopped and removed in finally; fixtures and command evidence remain.
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
root = Path(os.environ["GROUP_TEST_OUT"]).resolve()
root.mkdir(parents=True, exist_ok=False)
home = root / "home"
env = {key: value for key, value in os.environ.items()
       if key not in ("MSB_HOME", "MSB_CONFIG_PATH", "MSB_BACKEND", "MSB_PROFILE")}
env.update(MSB_HOME=str(home), MSB_BACKEND="local",
           MSB_CONFIG_PATH=str(home / "absent.json"), NO_COLOR="1")
layout = os.environ.get("GROUP_TEST_LAYOUT", "flat:512M")
full_only = layout.startswith("tmpfs:")
rows = []
names = []
groups = set()
passed = False


def run(label, *args, fail=False):
    started = time.perf_counter()
    result = subprocess.run([binary, *map(str, args)], env=env, capture_output=True,
                            text=True, stdin=subprocess.DEVNULL, timeout=180)
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


def create(name, snapshot=None, forked=False, checkpoint=None):
    names.append(name)
    if snapshot:
        # PR1 exercises the retained restore interface; canonical create/run launch
        # is introduced by PR2 and must not be assumed by this standalone suite.
        reference = f"{snapshot}:{checkpoint}" if checkpoint is not None else snapshot
        args = ["snapshot", "restore", reference, "--name", name]
    else:
        args = ["create", "--name", name, image, "--root-disk", layout,
                "--memory", "256M", "--cpus", "2"]
    if forked:
        args.append("--cow-mem")
    run("create-" + name, *args)


def capture(label, source, member, group="work", full=False, fail=False):
    # Initial creation binds a group. Later capture checks that exact source;
    # a restored child gets its own history even when it has shared ancestry.
    args = (["snapshot", "checkpoint", group] if group in groups
            else ["snapshot", "create", group])
    args += ["--sandbox", source, "--name", member, "--integrity"]
    if full or full_only:
        args.append("--full")
    output = run(label, *args, fail=fail)
    if fail:
        return None
    groups.add(group)
    path = Path(output.splitlines()[-1])
    descriptor = json.loads((path / "snapshot.json").read_text())
    assert path.parent == home / "snapshots" / group, path
    assert path.name == descriptor["snapshot_id"], path
    return path, descriptor


def head(label, group):
    return json.loads(run(label, "snapshot", "head", group, "--format", "json"))


def select(label, group, member):
    return json.loads(run(label, "snapshot", "modify", group, "--set-head", member,
                          "--format", "json"))


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

    create("old-child", "work", checkpoint="cp1")
    assert guest("read-old-child", "old-child", "cat /disk-marker") == "one"
    capture("cross-source-refused", "old-child", "forbidden", fail=True)
    branch, db = capture("capture-old-child", "old-child", "experiment", group="experiment-history")
    assert db["parent"] == d1["snapshot_id"]
    assert head("sibling-keeps-head", "work")["head"] == d2["snapshot_id"]
    assert head("separate-child-head", "experiment-history")["head"] == db["snapshot_id"]
    create("selected-child", "experiment-history")
    assert guest("read-selected-head", "selected-child", "cat /disk-marker") == "one"
    run("stop-selected-child", "stop", "selected-child")
    select("select-cp2", "work", "cp2")

    # Different children retain sibling ancestry, but never share a source-bound group.
    create("race-a", "work", checkpoint="cp2")
    create("race-b", "work", checkpoint="cp2")
    with ThreadPoolExecutor(max_workers=2) as pool:
        pending = [pool.submit(capture, "capture-" + child, child, child, group=child + "-history")
                   for child in ("race-a", "race-b")]
        siblings = [future.result() for future in pending]
    ids = {desc["snapshot_id"] for _, desc in siblings}
    assert all(desc["parent"] == d2["snapshot_id"] for _, desc in siblings)
    assert head("race-keeps-source-head", "work")["head"] == d2["snapshot_id"]
    assert len(ids) == 2
    assert all(path.exists() for path, _ in siblings)
    for name in ("old-child", "race-a", "race-b"):
        run("stop-" + name, "stop", name)
    select("select-cp2-again", "work", "cp2")

    # Full capture, direct local branch ancestry, and paused-source preservation.
    full1, f1 = capture("capture-full1", "source", "full1", full=True)
    assert f1["parent"] == d2["snapshot_id"]
    names.append("local-child")
    run("local-branch", "branch", "source", "--name", "local-child")
    local_snap, dl = capture("capture-local-child", "local-child", "local-child", group="local-history", full=True)
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
    run("export-base", "snapshot", "save", "work", base_archive, "--checkpoint", "full1")
    run("export-delta", "snapshot", "save", "work", delta_archive, "--checkpoint", "full2", "--since", full1)
    inventory = json.loads(subprocess.check_output(["tar", "-xOf", str(delta_archive), "archive.json"]))
    dependent = inventory["completeness"] == "dependent"
    # A RAM-only cut can have no reusable objects: --since then emits a standalone archive.
    # Require a base exactly when the archive actually omitted required payloads.
    run("missing-base" + ("-refused" if dependent else "-not-needed"), "snapshot", "load",
        "missing", "--file", delta_archive, fail=dependent)
    if dependent:
        assert not (home / "snapshots" / "missing").exists()
    run("import-base", "snapshot", "load", "received", "--file", base_archive)
    run("import-delta", "snapshot", "load", "received", "--file", delta_archive,
        "--base", "received:full1")
    assert head("import-advanced-head", "received")["head"] == f2["snapshot_id"]
    # Imported history has no source binding, even while the original still exists.
    run("unbound-capture-refused", "snapshot", "checkpoint", "received", fail=True)
    run("reimport-old", "snapshot", "load", "received", "--file", base_archive)
    assert head("old-import-kept-head", "received")["head"] == f2["snapshot_id"]
    run("reimport-set-head", "snapshot", "load", "received", "--file", base_archive, "--set-head")
    assert head("old-import-explicit-head", "received")["head"] == f1["snapshot_id"]
    select("select-removal-head", "received", "full2")
    run("remove-head", "snapshot", "remove", "received", "--checkpoint", "full2", "--force")
    assert head("head-parent-fallback", "received")["head"] == f1["snapshot_id"]
    run("restore-removed-member", "snapshot", "load", "received", "--file", delta_archive)
    run("clear-head", "snapshot", "modify", "received", "--clear-head")
    assert head("cleared-head", "received")["head"] is None
    run("headless-spawn-refused", "snapshot", "restore", "received",
        "--name", "headless-child", fail=True)
    select("restore-head-selection", "received", "full2")

    run("import-second-group", "snapshot", "load", "duplicate", "--file", base_archive)
    run("inspect-exact-duplicate", "snapshot", "inspect", "duplicate", "--checkpoint", f1["snapshot_id"])
    assert head("duplicate-keeps-identity", "duplicate")["head"] == f1["snapshot_id"]
    run("reindex", "snapshot", "reindex")
    for mode in ("eager", "forked"):
        child = "restored-" + mode
        create(child, "received", forked=mode == "forked", checkpoint="full2")
        assert guest("restored-state-" + mode, child,
                     "cat /disk-marker; cat /dev/shm/marker") == "three\nram-three"
        run("stop-" + child, "stop", child)

    # Direct archive capture records ancestry but never creates an installed member.
    before_members = sorted(str(p) for p in (home / "snapshots").rglob("snapshot.json"))
    direct = root / "direct.msb"
    run("direct-capture", "snapshot", "create", "--sandbox", "source", "--name", "direct", "--full", "--output", direct)
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
        create("stopped-restored", "work", checkpoint="stopped")
        assert guest("stopped-restored-state", "stopped-restored", "cat /disk-marker") == "three"
    passed = True
finally:
    cleanup = []
    for name in reversed(names):
        for action in ("stop", "rm"):
            try:
                result = subprocess.run([binary, action, name], env=env, capture_output=True,
                                        text=True, stdin=subprocess.DEVNULL, timeout=30)
                cleanup.append({"name": name, "action": action, "exit": result.returncode})
                (root / ("cleanup-" + action + "-" + name + ".log")).write_text(result.stdout + result.stderr)
                if result.returncode:
                    passed = False
            except subprocess.TimeoutExpired:
                cleanup.append({"name": name, "action": action, "timeout": True})
                passed = False
    (root / "results.json").write_text(json.dumps(rows, indent=2))
    report = {"pass": passed, "layout": layout, "commands": len(rows), "cleanup": cleanup}
    (root / "report.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report), flush=True)
if not passed:
    raise RuntimeError("group qualification or cleanup failed; inspect report.json")
