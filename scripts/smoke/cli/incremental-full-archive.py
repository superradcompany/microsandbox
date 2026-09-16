#!/usr/bin/env python3
"""Opt-in full archive dependency chain: real guest RAM/disk, eager/forked restore, cleanup.

Set MSB_PATH, STACK8_OUT, and optionally STACK8_LAYOUT (512M, flat:512M, tmpfs:128M).
Each run creates isolated source/destination MSB_HOME directories below STACK8_OUT.
"""

import json
import os
from pathlib import Path
import shutil
import subprocess
import time

binary = os.environ["MSB_PATH"]
root = Path(os.environ["STACK8_OUT"])
root.mkdir(parents=True, exist_ok=False)
layout = os.environ.get("STACK8_LAYOUT", "flat:512M")
source_home = root / "source-home"
dest_home = root / "destination-home"
prefix = f"ramdelta-{os.getpid()}"
rows = []
names = []


def run(label, home, *args, fail=False):
    env = dict(os.environ, MSB_HOME=str(home))
    started = time.perf_counter()
    result = subprocess.run([binary, *map(str, args)], env=env, capture_output=True, text=True, timeout=180)
    elapsed = round((time.perf_counter() - started) * 1000, 2)
    (root / f"{label}.stdout").write_text(result.stdout)
    (root / f"{label}.stderr").write_text(result.stderr)
    rows.append({"case": label, "ms": elapsed, "exit": result.returncode})
    print(json.dumps(rows[-1]), flush=True)
    if (result.returncode != 0) != fail:
        raise RuntimeError(f"{label}: exit={result.returncode}: {result.stderr[-3000:]}")
    return result.stdout.strip()


def guest(label, home, name, script):
    return run(label, home, "exec", name, "--", "sh", "-ec", script)


def inventory(archive):
    # System tar decodes plain and zstd input by magic, independently of the SDK loader.
    return json.loads(subprocess.check_output(["tar", "-xOf", str(archive), "archive.json"]))


def restore(label, snapshot, expected, base=None, forked=False):
    name = prefix + "-" + label
    names.append((dest_home, name))
    args = ["create", "--name", name, "--from-snapshot", str(snapshot)]
    if base:
        args += ["--snapshot-base", str(base)]
    if forked:
        args += ["--forked"]
    run(label, dest_home, *args)
    actual = guest(label + "-read", dest_home, name, "cat /dev/shm/marker; cat /disk-marker; sha256sum /dev/shm/blob | cut -d' ' -f1")
    assert actual == f"{expected}\n{expected}\n{blob_hash}", actual
    guest(label + "-write", dest_home, name, "echo child > /dev/shm/marker; echo child > /disk-marker")
    return name


try:
    source = prefix + "-source"
    names.append((source_home, source))
    # Reuse only immutable OCI artifacts, never a prior VM or memory backing cache.
    seed = os.environ.get("STACK8_SEED_CACHE")
    if seed:
        for kind in ("layers", "manifests", "fsmeta", "vmdk"):
            origin = Path(seed) / kind
            if origin.exists():
                shutil.copytree(origin, source_home / "cache" / kind)
    run("boot", source_home, "create", "alpine", "--name", source, "--root-disk", layout, "--memory", "256M", "--cpus", "2")
    # Image transport is separate from checkpoint dependencies. Independently populate the
    # destination's OCI cache so this matrix does not depend on --with-image or source paths.
    seed_vm = prefix + "-image-seed"
    names.append((dest_home, seed_vm))
    run("prepare-destination-image", dest_home, "create", "alpine", "--name", seed_vm, "--root-disk", layout, "--memory", "256M", "--cpus", "2")
    run("stop-image-seed", dest_home, "stop", seed_vm)
    blob_hash = guest("prepare", source_home, source, "dd if=/dev/urandom of=/dev/shm/blob bs=1M count=24 2>/dev/null; sha256sum /dev/shm/blob | cut -d' ' -f1")
    previous_source = None
    installed_base = None
    archive_rows = []
    for n in range(1, 13):
        guest(f"mutate-{n}", source_home, source, f"echo {n} > /dev/shm/marker; echo {n} > /disk-marker; dd if=/dev/zero of=/dev/shm/zero bs=4096 count=1 2>/dev/null")
        if n == 6:
            run("pause-source", source_home, "pause", source)
        name = f"cp{n:02}"
        run(f"capture-{n}", source_home, "snapshot", "create", name, "--from-sandbox", source, "--full")
        if n == 6:
            run("resume-source", source_home, "resume", source)
        artifact = source_home / "snapshots" / name
        archive = root / f"cp{n:02}.msb"
        args = ["snapshot", "save", artifact, archive]
        if previous_source:
            args += ["--since", previous_source]
        run(f"export-{n}", source_home, *args)
        inv = inventory(archive)
        omitted_ram = [e for e in inv["entries"] if not e["included"] and e["kind"] == "checkpoint-object"]
        if n > 1:
            assert omitted_ram, "incremental export did not omit any reusable RAM objects"
        assert all(e["kind"] in ("checkpoint-object", "checkpoint-disk-layer") for e in inv["entries"] if not e["included"])
        archive_rows.append({"checkpoint": n, "archive_bytes": archive.stat().st_size, "omitted_ram_objects": len(omitted_ram), "omitted_ram_bytes": sum(e["apparent_size"] for e in omitted_ram)})
        if n == 2:
            run("missing-base", dest_home, "snapshot", "load", archive, fail=True)
            run("wrong-base", dest_home, "snapshot", "load", archive, "--base", root / "absent", fail=True)
        if n == 12:
            final_archive, final_artifact = archive, artifact
            break
        load_args = ["snapshot", "load", archive]
        if installed_base:
            load_args += ["--base", installed_base]
        old_base = installed_base
        installed_base = Path(run(f"load-{n}", dest_home, *load_args).splitlines()[-1])
        assert installed_base.parent == dest_home / "snapshots"
        if old_base:
            run(f"remove-base-{n-1}", dest_home, "snapshot", "remove", old_base)
        previous_source = artifact
    run("stop-source", source_home, "stop", source)
    before = set((dest_home / "snapshots").iterdir())
    eager = restore("direct-eager", final_archive, 12, installed_base)
    forked = restore("direct-forked", final_archive, 12, installed_base, True)
    assert set((dest_home / "snapshots").iterdir()) == before, "direct restore installed the target snapshot"
    final_loaded = Path(run("load-final", dest_home, "snapshot", "load", final_archive, "--base", installed_base).splitlines()[-1])
    run("remove-final-base", dest_home, "snapshot", "remove", installed_base)
    # Live children must retain both their captured RAM backing and private disk writes
    # after the explicit base disappears. The installed target must remain independent too.
    for mode, child in (("eager", eager), ("forked", forked)):
        actual = guest("deleted-base-" + mode, dest_home, child, "cat /dev/shm/marker; cat /disk-marker; sha256sum /dev/shm/blob | cut -d' ' -f1")
        assert actual == f"child\nchild\n{blob_hash}", actual
        run("stop-" + mode, dest_home, "stop", child)
    run("verify-final", dest_home, "snapshot", "verify", final_loaded)
    for mode in ("eager", "forked"):
        child = restore("installed-" + mode, final_loaded, 12, forked=mode == "forked")
        run("stop-installed-" + mode, dest_home, "stop", child)
    complete = root / "standalone.msb"
    run("export-standalone", source_home, "snapshot", "save", final_artifact, complete)
    assert all(e["included"] for e in inventory(complete)["entries"])
    archive_rows[-1]["standalone_bytes"] = complete.stat().st_size
    (root / "archive-sizes.json").write_text(json.dumps(archive_rows, indent=2))
    print(json.dumps({"pass": True, "layout": layout, "archives": archive_rows}), flush=True)
finally:
    # Stop only test-owned names, including children whose creation failed part-way through.
    for home, name in reversed(names):
        result = subprocess.run([binary, "stop", name], env=dict(os.environ, MSB_HOME=str(home)), capture_output=True, text=True, timeout=30)
        (root / ("cleanup-" + name + ".log")).write_text(result.stdout + result.stderr)
    (root / "results.json").write_text(json.dumps(rows, indent=2))
