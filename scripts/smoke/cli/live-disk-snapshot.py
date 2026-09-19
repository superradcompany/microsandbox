#!/usr/bin/env python3
"""Live disk-only capture on an isolated MSB_HOME with a matching runtime/firmware.

MSB_PATH, MSB_HOME, STACK8_PREFIX and STACK8_OUT are required. The fixture stops
its own VMs and records whole CLI times, not just the VM pause interval.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

binary = os.environ["MSB_PATH"]
home = Path(os.environ["MSB_HOME"])
out = Path(os.environ["STACK8_OUT"])
out.mkdir(parents=True, exist_ok=True)
prefix = os.environ["STACK8_PREFIX"]
rows = []
names = []


def run(label, *args, ok=True):
    start = time.monotonic()
    result = subprocess.run([binary, *args], capture_output=True, text=True, timeout=180)
    row = dict(case=label, ms=round((time.monotonic() - start) * 1000, 2),
               exit=result.returncode, stdout=result.stdout, stderr=result.stderr)
    rows.append(row)
    (out / "results.json").write_text(json.dumps(rows, indent=2))
    if ok:
        assert result.returncode == 0, row
    return result


def files(root):
    return {str(p.relative_to(root)): (p.stat().st_size, p.stat().st_mtime_ns)
            for p in root.rglob("*") if p.is_file()} if root.exists() else {}


def sealed_hashes(root):
    result = {}
    for path in root.rglob("*"):
        if path.is_file() and path.suffix in (".raw", ".qcow2", ".ext4"):
            digest = hashlib.sha256()
            with path.open("rb") as file:
                for chunk in iter(lambda: file.read(1024 * 1024), b""):
                    digest.update(chunk)
            result[str(path)] = digest.hexdigest()
    assert result
    return result


try:
    for layout in ("flat", "managed"):
        source = prefix + "-" + layout
        names.append(source)
        run("create-" + layout, "create", "alpine", "--name", source,
            "--root-disk", "flat:512M" if layout == "flat" else "512M", "--memory", "256M")
        run("prepare-" + layout, "exec", source, "--", "sh", "-c",
            "echo before > /disk-marker; echo ram-only > /dev/shm/ram-marker; sync")
        boot = run("boot-" + layout, "exec", source, "--", "cat", "/proc/sys/kernel/random/boot_id").stdout
        runtime = home / "sandboxes" / source / "runtime"
        memory_before = files(runtime / "checkpoint-store")
        cache_before = files(home / "cache" / "memory")
        for mode in ("installed", "integrity", "archive", "plain", "paused"):
            snap = source + "-" + mode
            child = snap + "-child"
            names.append(child)
            run("reset-" + snap, "exec", source, "--", "sh", "-c", "echo before > /disk-marker; sync")
            if mode == "paused":
                run("pause-" + layout, "pause", source)
            args = ["snapshot", "create", snap, "--from-sandbox", source]
            archive = out / (snap + (".tar" if mode == "plain" else ".msb"))
            installed_before = set((home / "snapshots").glob("*"))
            if mode in ("archive", "plain"):
                args += ["--output", str(archive)]
                if mode == "plain":
                    args += ["--plain-tar"]
            if mode == "integrity":
                args += ["--integrity"]
            run("capture-" + snap, *args)
            assert files(runtime / "checkpoint-store") == memory_before, "disk capture touched the RAM/object store"
            assert files(home / "cache" / "memory") == cache_before, "disk capture touched the RAM cache"
            assert not list((runtime / "checkpoints").iterdir()), "consumed disk staging leaked"
            if mode == "paused":
                # Public repeated pause must be idempotent, and an exec must not release it.
                paused_exec = run("paused-exec-" + layout, "exec", source, "--", "true", ok=False)
                assert paused_exec.returncode != 0
                run("resume-" + layout, "resume", source)
            assert run("source-boot-" + snap, "exec", source, "--", "cat", "/proc/sys/kernel/random/boot_id").stdout == boot
            assert run("source-ram-" + snap, "exec", source, "--", "cat", "/dev/shm/ram-marker").stdout.strip() == "ram-only"
            run("diverge-" + snap, "exec", source, "--", "sh", "-c", "echo after > /disk-marker; sync")
            if mode in ("archive", "plain"):
                assert set((home / "snapshots").glob("*")) == installed_before, "direct archive installed a snapshot"
                from_snapshot = str(archive)
            else:
                artifact = home / "snapshots" / snap
                manifest = json.loads((artifact / "snapshot.json").read_text())
                assert manifest["scope"] == "file" and manifest["state"]["kind"] == "file", manifest
                assert not (artifact / "checkpoint").exists()
                before = sealed_hashes(artifact)
                from_snapshot = snap
            run("restore-" + snap, "create", "--name", child, "--from-snapshot", from_snapshot)
            assert run("child-disk-" + snap, "exec", child, "--", "cat", "/disk-marker").stdout.strip() == "before"
            run("child-no-ram-" + snap, "exec", child, "--", "sh", "-c", "test ! -e /dev/shm/ram-marker")
            assert run("child-boot-" + snap, "exec", child, "--", "cat", "/proc/sys/kernel/random/boot_id").stdout != boot
            run("child-write-" + snap, "exec", child, "--", "sh", "-c", "echo child > /disk-marker; sync")
            assert run("source-disk-" + snap, "exec", source, "--", "cat", "/disk-marker").stdout.strip() == "after"
            if mode in ("archive", "plain"):
                archive.unlink()
            else:
                assert sealed_hashes(artifact) == before, "source or child mutated sealed layers"
                run("remove-" + snap, "snapshot", "remove", snap)
            assert run("after-delete-" + snap, "exec", child, "--", "cat", "/disk-marker").stdout.strip() == "child"
            run("stop-child-" + snap, "stop", child)
        # Exercise the cut while the guest actually submits writes, not only after sync.
        # Keep ownership in the guest, as in the branch timer fixture. This does not depend
        # on an additional host client's stdin/console lifetime while capture runs.
        run("start-writer-" + layout, "exec", source, "--", "sh", "-c",
            "sh -c 'i=1; while [ ! -e /stop-counter ]; do echo $i > /counter.tmp; "
            "mv /counter.tmp /counter; sync; i=$((i+1)); sleep 0.02; done; "
            "touch /counter-done' >/tmp/counter.log 2>&1 </dev/null &")
        run("wait-writer-" + layout, "exec", source, "--", "sh", "-c",
            "for i in $(seq 1 100); do [ -s /counter ] && exit 0; sleep 0.02; done; exit 1")
        start_counter = int(run("counter-before-" + layout, "exec", source, "--", "cat", "/counter").stdout.strip())
        run("counter-baseline-sync-" + layout, "exec", source, "--", "sync")
        run("busy-capture-" + layout, "snapshot", "create", source + "-busy", "--from-sandbox", source)
        run("counter-progress-" + layout, "exec", source, "--", "sh", "-c",
            f"for i in $(seq 1 100); do [ $(cat /counter) -gt {start_counter} ] && exit 0; sleep 0.02; done; exit 1")
        run("stop-writer-" + layout, "exec", source, "--", "touch", "/stop-counter")
        run("writer-stopped-" + layout, "exec", source, "--", "sh", "-c",
            "for i in $(seq 1 100); do [ -e /counter-done ] && exit 0; sleep 0.02; done; exit 1")
        busy_child = source + "-busy-child"
        names.append(busy_child)
        run("busy-restore-" + layout, "create", "--name", busy_child, "--from-snapshot", source + "-busy")
        assert int(run("busy-restored-counter-" + layout, "exec", busy_child, "--", "cat", "/counter").stdout.strip()) >= start_counter
        run("stop-busy-child-" + layout, "stop", busy_child)
        # A later full checkpoint must still work after disk-only generations.
        full = source + "-full"
        run("full-after-disk-" + layout, "snapshot", "create", full, "--from-sandbox", source, "--full")
        full_child = source + "-full-child"
        names.append(full_child)
        run("full-restore-" + layout, "create", "--name", full_child, "--from-snapshot", full)
        assert run("full-ram-" + layout, "exec", full_child, "--", "cat", "/dev/shm/ram-marker").stdout.strip() == "ram-only"
        # A disk-only cut between full captures must not consume/advance the RAM baseline.
        memory_before = files(runtime / "checkpoint-store")
        run("disk-between-full-" + layout, "snapshot", "create", source + "-between", "--from-sandbox", source)
        assert files(runtime / "checkpoint-store") == memory_before
        run("change-ram-" + layout, "exec", source, "--", "sh", "-c", "echo updated > /dev/shm/ram-marker")
        run("second-full-" + layout, "snapshot", "create", full + "-next", "--from-sandbox", source, "--full")
        next_child = source + "-next-child"
        names.append(next_child)
        run("second-full-restore-" + layout, "create", "--name", next_child, "--from-snapshot", full + "-next")
        assert run("second-full-ram-" + layout, "exec", next_child, "--", "cat", "/dev/shm/ram-marker").stdout.strip() == "updated"
        # A name collision must fail before publication and leave both the source and snapshot usable.
        refused = run("duplicate-refused-" + layout, "snapshot", "create", source + "-between", "--from-sandbox", source, ok=False)
        assert refused.returncode != 0
        run("source-after-refusal-" + layout, "exec", source, "--", "true")
        run("stop-source-" + layout, "stop", source)
        run("stopped-after-live-" + layout, "snapshot", "create", source + "-stopped", "--from-sandbox", source)
    tmpfs = prefix + "-tmpfs"
    names.append(tmpfs)
    run("tmpfs-create", "create", "alpine", "--name", tmpfs, "--root-disk", "tmpfs:128M", "--memory", "256M")
    refused = run("tmpfs-refused", "snapshot", "create", tmpfs + "-bad", "--from-sandbox", tmpfs, ok=False)
    assert refused.returncode != 0 and "tmpfs" in refused.stderr
    run("tmpfs-still-running", "exec", tmpfs, "--", "true")
    print(json.dumps({"result": "pass", "layouts": ["flat", "managed"], "modes": ["installed", "integrity", "archive", "plain", "paused"]}))
finally:
    for name in reversed(names):
        try:
            run("cleanup-" + name, "stop", name, ok=False)
        except Exception as error:
            rows.append({"case": "cleanup-" + name, "error": str(error)})
    (out / "results.json").write_text(json.dumps(rows, indent=2))
