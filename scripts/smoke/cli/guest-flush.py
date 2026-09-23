#!/usr/bin/env python3
"""Exercise guest-flush semantics with a real VM in a fresh, isolated home.

Use --baseline to measure the released behavior without policy flags. Baseline
results are deliberately not treated as evidence of guest-flush enforcement.
The script retains artifacts and JSON timings, but stops every VM it creates.
"""

import argparse
import json
import os
from pathlib import Path
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--msb", type=Path, required=True)
    parser.add_argument("--firmware", type=Path, required=True)
    parser.add_argument("--home", type=Path, required=True)
    parser.add_argument("--baseline", action="store_true")
    parser.add_argument("--legacy-msb", type=Path, help="Released runtime for capability refusal tests")
    parser.add_argument("--benchmark-repetitions", type=int, default=0,
                        help="Measure fresh sources, alternating policies and an optional released baseline")
    parser.add_argument("--owned-disk-mib", type=int, default=0,
                        help="Exercise dirty root + owned block disks with this many MiB on each; --baseline records old policy behavior")
    args = parser.parse_args()
    home = args.home.resolve()
    if home.exists():
        parser.error("--home must not exist; use a new path for each run")
    binary = args.msb.resolve(strict=True)
    firmware = args.firmware.resolve(strict=True)
    home.mkdir(parents=True, mode=0o700)
    env = dict(os.environ, MSB_HOME=str(home), MSB_PATH=str(binary),
               MSB_LIBKRUNFW_PATH=str(firmware))
    rows, names = [], []
    report = home / "guest-flush-results.json"
    completed = False

    def save():
        report.write_text(json.dumps({
            "baseline": args.baseline,
            "completed": completed,
            "binary": str(binary),
            "rows": rows,
        }, indent=2) + "\n")

    def run(label, *command, expect_success=True, executable=None):
        started = time.monotonic()
        try:
            selected = str(executable or binary)
            result = subprocess.run([selected, *command], env=dict(env, MSB_PATH=selected),
                                    capture_output=True, text=True, timeout=180)
        except subprocess.TimeoutExpired:
            rows.append({"case": label, "timeout": True,
                         "ms": round((time.monotonic() - started) * 1000, 3)})
            save()
            raise
        row = {"case": label, "ms": round((time.monotonic() - started) * 1000, 3),
               "exit": result.returncode, "stdout": result.stdout,
               "stderr": result.stderr}
        rows.append(row)
        save()
        if expect_success:
            assert result.returncode == 0, row
        return result

    def shell(name, command):
        return run("exec-" + name, "exec", name, "--", "sh", "-c", command)

    def stop(name):
        stopped = run("stop-" + name, "stop", name, expect_success=False)
        if stopped.returncode:
            # Targets are confined to names created by this run in a new MSB_HOME.
            run("kill-" + name, "kill", name)

    def state(name):
        items = json.loads(run("status-" + name, "list", "--format", "json").stdout)
        return next(item["status"].lower() for item in items if item["name"] == name)

    def refused(label, *command):
        result = run(label, *command, expect_success=False)
        assert result.returncode != 0, result.stdout
        assert "flush" in result.stderr.lower() or "writeback" in result.stderr.lower(), result.stderr

    try:
        run("version", "--version")
        if args.owned_disk_mib:
            assert 0 < args.owned_disk_mib <= 512
            # Enough RAM and long writeback intervals keep both files dirty until capture.
            # Use a fresh source per case; a preceding Required capture must not clean Skip's input.
            for layout, root in [("managed", "2G"), ("flat", "flat:2G")]:
                for operation in ("pause", "disk", "full", "branch"):
                    for policy in ("auto", "required", "skip"):
                        label = f"owned-{layout}-{operation}-{policy}"
                        source, child = "b-" + label, "c-" + label
                        names.append(source)
                        run("create-" + label, "create", "alpine", "--name", source,
                            "--root-disk", root, "--memory", "4G", "--max-duration", "30m",
                            "--mount-owned", "/data:kind=disk,size=2G")
                        shell(source, "set -e; echo 99 > /proc/sys/vm/dirty_background_ratio; "
                              "echo 99 > /proc/sys/vm/dirty_ratio; "
                              "echo 60000 > /proc/sys/vm/dirty_writeback_centisecs; "
                              "echo 60000 > /proc/sys/vm/dirty_expire_centisecs; "
                              f"dd if=/dev/urandom of=/flush-data bs=1M count={args.owned_disk_mib} 2>/dev/null; "
                              "cp /flush-data /data/data; echo retained-ram > /dev/shm/flush-marker")
                        checksum = shell(source, "sha256sum /flush-data").stdout.split()[0]
                        dirty_cmd = "awk '/^Dirty:/ {print $2}' /proc/meminfo"
                        dirty_before = int(shell(source, dirty_cmd).stdout.strip())
                        assert dirty_before >= args.owned_disk_mib * 1024 * 1.5, (label, dirty_before)
                        # Plain pause is important: it must not flush solely because a disk is owned.
                        flags = [] if operation == "pause" and policy == "auto" else ["--guest-flush", policy]
                        if operation == "pause":
                            run("measure-" + label, "pause", source, *flags)
                            assert state(source) == "paused"
                            if not args.baseline and policy != "required":
                                refused("unflushed-paused-" + label, "snapshot", "create", "must-refuse",
                                        "--from-sandbox", source, "--guest-flush", "required")
                                assert state(source) == "paused"
                            run("resume-" + label, "resume", source)
                        elif operation == "branch":
                            names.append(child)
                            run("measure-" + label, "branch", source, "--name", child, *flags)
                        else:
                            archive = home / (label + ".msb")
                            scope = ["--full"] if operation == "full" else []
                            run("measure-" + label, "snapshot", "create", label,
                                "--from-sandbox", source, "-o", str(archive), *scope, *flags)
                        dirty_after = int(shell(source, dirty_cmd).stdout.strip())
                        rows.append({"case": "dirty-" + label, "before_kib": dirty_before, "after_kib": dirty_after})
                        save()
                        flush_expected = policy == "required" or (operation == "disk" and policy == "auto")
                        if not args.baseline:
                            if flush_expected:
                                assert dirty_after < dirty_before / 4, (label, dirty_before, dirty_after)
                            else:
                                assert dirty_after > dirty_before / 2, (label, dirty_before, dirty_after)
                        if operation in ("disk", "full"):
                            names.append(child)
                            run("restore-" + label, "restore", str(archive), "--name", child)
                        if operation != "pause":
                            if operation != "disk" or flush_expected:
                                for path in ("/flush-data", "/data/data"):
                                    assert shell(child, "sha256sum " + path).stdout.split()[0] == checksum
                            if operation != "disk":
                                assert shell(child, "cat /dev/shm/flush-marker").stdout.strip() == "retained-ram"
                            shell(child, "echo private > /flush-data; echo private > /data/data")
                            for path in ("/flush-data", "/data/data"):
                                assert shell(source, "sha256sum " + path).stdout.split()[0] == checksum
                            stop(child)
                        stop(source)
            completed = True
            return
        if args.benchmark_repetitions:
            assert args.benchmark_repetitions > 0
            variants = [("auto", binary), ("required", binary), ("skip", binary)]
            if args.legacy_msb:
                variants.append((None, args.legacy_msb.resolve(strict=True)))
            # Each sample starts from fresh disks/RAM: accumulated backing chains or
            # a previous full capture's incremental baseline must not bias the policy.
            for trial in range(args.benchmark_repetitions):
                ordered = variants[trial % len(variants):] + variants[:trial % len(variants)]
                for layout, root in [("managed", "512M"), ("flat", "flat:512M")]:
                    for operation in ("disk", "full", "branch", "pause"):
                        for policy, executable in ordered:
                            label = f"{layout}-{operation}-{policy or 'baseline'}-{trial}"
                            source, child = "b-" + label, "c-" + label
                            names.append(source)
                            run("create-" + label, "create", "alpine", "--name", source,
                                "--root-disk", root, "--memory", "256M", "--max-duration", "30m",
                                executable=executable)
                            shell(source, "echo 60000 > /proc/sys/vm/dirty_writeback_centisecs; "
                                  "echo 60000 > /proc/sys/vm/dirty_expire_centisecs; "
                                  "dd if=/dev/urandom of=/flush-data bs=1M count=8 2>/dev/null; "
                                  "echo retained-ram > /dev/shm/flush-marker")
                            flags = ["--guest-flush", policy] if policy else []
                            if operation == "pause":
                                run("measure-" + label, "pause", source, *flags, executable=executable)
                                run("resume-" + label, "resume", source, executable=executable)
                            elif operation == "branch":
                                names.append(child)
                                run("measure-" + label, "branch", source, "--name", child,
                                    *flags, executable=executable)
                            else:
                                archive = home / (label + ".msb")
                                scope = ["--full"] if operation == "full" else []
                                run("measure-" + label, "snapshot", "create", label,
                                    "--from-sandbox", source, "-o", str(archive),
                                    *scope, *flags, executable=executable)
                                names.append(child)
                                run("restore-" + label, "restore", str(archive), "--name", child,
                                    executable=executable)
                                rows[-1]["archive_bytes"] = archive.stat().st_size
                            if operation in ("full", "branch"):
                                assert shell(child, "cat /dev/shm/flush-marker").stdout.strip() == "retained-ram"
                            if operation != "pause":
                                stop(child)
                            stop(source)
            completed = True
            return
        for layout, root in [("managed", "512M"), ("flat", "flat:512M")]:
            source = "flush-" + layout
            names.append(source)
            run("create-" + layout, "create", "alpine", "--name", source,
                "--root-disk", root, "--memory", "256M", "--max-duration", "30m")
            boot = shell(source, "cat /proc/sys/kernel/random/boot_id").stdout.strip()
            shell(source, "echo retained-ram > /dev/shm/flush-marker")
            # Keep small writes dirty long enough to expose the difference between
            # preserving RAM and capturing only disk. Do not use sync in this path.
            shell(source, "echo 60000 > /proc/sys/vm/dirty_writeback_centisecs; "
                  "echo 60000 > /proc/sys/vm/dirty_expire_centisecs")
            policies = [None] if args.baseline else ["auto", "required", "skip"]
            for full in (False, True):
                for policy in policies:
                    mode = "full" if full else "disk"
                    label = f"{layout}-{mode}-{policy or 'baseline'}"
                    # Data is incompressible enough to avoid measuring only zero handling.
                    shell(source, "dd if=/dev/urandom of=/flush-data bs=1M count=8 2>/dev/null; "
                          "echo captured > /flush-marker")
                    checksum = shell(source, "sha256sum /flush-data").stdout.split()[0]
                    archive = home / (label + ".msb")
                    command = ["snapshot", "create", label, "--from-sandbox", source,
                               "-o", str(archive)]
                    if full:
                        command.append("--full")
                    if policy:
                        command += ["--guest-flush", policy]
                    installed = set((home / "snapshots").rglob("snapshot.json"))
                    run("capture-" + label, *command)
                    assert shell(source, "cat /proc/sys/kernel/random/boot_id").stdout.strip() == boot
                    assert shell(source, "cat /dev/shm/flush-marker").stdout.strip() == "retained-ram"
                    # No installed snapshot may be a side effect of direct capture.
                    assert set((home / "snapshots").rglob("snapshot.json")) == installed
                    child = "child-" + label
                    names.append(child)
                    run("restore-" + label, "restore", str(archive), "--name", child)
                    restored = shell(child, "sha256sum /flush-data 2>/dev/null || true").stdout.split()
                    # Unflushed disk-only capture has no promise to retain the write.
                    if full or (not args.baseline and policy != "skip"):
                        assert restored and restored[0] == checksum, (label, restored, checksum)
                    if full:
                        assert shell(child, "cat /dev/shm/flush-marker").stdout.strip() == "retained-ram"
                        shell(child, "echo private > /dev/shm/flush-marker")
                        assert shell(source, "cat /dev/shm/flush-marker").stdout.strip() == "retained-ram"
                    else:
                        shell(child, "test ! -e /dev/shm/flush-marker")
                    stop(child)
                    if full and policy == "required":
                        disk_child = "disk-" + label
                        names.append(disk_child)
                        run("disk-projection-" + label, "restore", str(archive),
                            "--name", disk_child, "--disk-only")
                        assert shell(disk_child, "sha256sum /flush-data").stdout.split()[0] == checksum
                        stop(disk_child)
            if not args.baseline:
                # An ordinary pause does not prove a root flush, even if the empty
                # external-mount request received a successful acknowledgement.
                run("pause-auto-" + layout, "pause", source)
                assert state(source) == "paused"
                failed = home / (layout + "-must-not-publish.msb")
                refused("paused-auto-disk-refused-" + layout, "snapshot", "create",
                        "unflushed", "--from-sandbox", source, "-o", str(failed))
                refused("paused-required-full-refused-" + layout, "snapshot", "create",
                        "unflushed-full", "--from-sandbox", source, "--full",
                        "--guest-flush", "required", "-o", str(failed))
                refused("paused-required-pause-refused-" + layout, "pause", source,
                        "--guest-flush", "required")
                assert not failed.exists()
                assert state(source) == "paused"
                run("paused-skip-disk-" + layout, "snapshot", "create", "paused-skip",
                    "--from-sandbox", source, "--guest-flush", "skip")
                assert state(source) == "paused"
                run("resume-unflushed-" + layout, "resume", source)
                assert shell(source, "cat /dev/shm/flush-marker").stdout.strip() == "retained-ram"

                # Required pause establishes coverage reusable for both capture kinds.
                run("pause-required-" + layout, "pause", source, "--guest-flush", "required")
                for full in (False, True):
                    label = "paused-" + ("full" if full else "disk")
                    command = ["snapshot", "create", label, "--from-sandbox", source,
                               "--guest-flush", "required"]
                    if full:
                        command.append("--full")
                    run(label + "-" + layout, *command)
                    assert state(source) == "paused"
                child = "paused-branch-" + layout
                names.append(child)
                run("branch-paused-" + layout, "branch", source, "--name", child,
                    "--guest-flush", "required")
                assert state(source) == "paused"
                assert shell(child, "cat /dev/shm/flush-marker").stdout.strip() == "retained-ram"
                stop(child)
                run("resume-required-" + layout, "resume", source)
                for policy in ("auto", "required", "skip"):
                    children = [f"batch-{layout}-{policy}-{i}" for i in range(2)]
                    names.extend(children)
                    run("batch-" + layout + "-" + policy, "branch", source,
                        "--guest-flush", policy, "--names", *children)
                    for child in children:
                        assert shell(child, "cat /dev/shm/flush-marker").stdout.strip() == "retained-ram"
                        stop(child)
                assert shell(source, "cat /proc/sys/kernel/random/boot_id").stdout.strip() == boot
            stop(source)
            if not args.baseline:
                refused("stopped-required-" + layout, "snapshot", "create", "stopped-required",
                        "--from-sandbox", source, "--guest-flush", "required")
                for policy in ("auto", "skip"):
                    run("stopped-" + layout + "-" + policy, "snapshot", "create", "stopped-" + policy,
                        "--from-sandbox", source, "--guest-flush", policy)
        if not args.baseline:
            source = "flush-owned"
            names.append(source)
            run("create-owned", "create", "alpine", "--name", source, "--memory", "256M",
                "--root-disk", "512M", "--mount-owned", "/data:kind=disk,size=256M",
                "--mount-owned", "/files", "--max-duration", "30m")
            shell(source, "echo 60000 > /proc/sys/vm/dirty_writeback_centisecs; "
                  "echo 60000 > /proc/sys/vm/dirty_expire_centisecs; "
                  "echo retained-ram > /dev/shm/flush-marker")
            for full in (False, True):
                for policy in ("auto", "required", "skip"):
                    label = f"owned-{'full' if full else 'disk'}-{policy}"
                    shell(source, "dd if=/dev/urandom of=/data/data bs=1M count=8 2>/dev/null; "
                          "cp /data/data /files/data; cp /data/data /flush-data")
                    checksum = shell(source, "sha256sum /data/data").stdout.split()[0]
                    archive = home / (label + ".msb")
                    command = ["snapshot", "create", label, "--from-sandbox", source,
                               "--guest-flush", policy, "-o", str(archive)]
                    if full:
                        command.append("--full")
                    run("capture-" + label, *command)
                    child = "child-" + label
                    names.append(child)
                    run("restore-" + label, "restore", str(archive), "--name", child)
                    for path in ("/data/data", "/files/data", "/flush-data"):
                        # Directory writeback is mandatory, but does not certify the
                        # independent root or owned block filesystems under disk Skip.
                        if full or policy != "skip" or path == "/files/data":
                            assert shell(child, "sha256sum " + path).stdout.split()[0] == checksum
                    shell(child, "echo private > /data/data; echo private > /files/data")
                    assert shell(source, "sha256sum /data/data").stdout.split()[0] == checksum
                    assert shell(source, "sha256sum /files/data").stdout.split()[0] == checksum
                    stop(child)
            # Directory synchronization alone must not certify root/owned block flush.
            run("pause-owned-auto", "pause", source)
            refused("capture-owned-paused-unflushed", "snapshot", "create", "owned-unflushed",
                    "--from-sandbox", source, "--guest-flush", "required")
            assert state(source) == "paused"
            run("resume-owned-unflushed", "resume", source)
            run("pause-owned-required", "pause", source, "--guest-flush", "required")
            run("capture-owned-paused", "snapshot", "create", "owned-paused",
                "--from-sandbox", source, "--guest-flush", "required")
            assert state(source) == "paused"
            run("resume-owned", "resume", source)
            stop(source)

            if args.legacy_msb:
                source = "flush-legacy"
                names.append(source)
                run("create-legacy", "create", "alpine", "--name", source,
                    "--memory", "256M", "--root-disk", "512M", "--max-duration", "30m",
                    executable=args.legacy_msb.resolve(strict=True))
                shell(source, "echo retained-ram > /dev/shm/flush-marker")
                for policy in ("auto", "required", "skip"):
                    archive = home / ("legacy-disk-" + policy + ".msb")
                    refused("legacy-disk-refuses-" + policy, "snapshot", "create", "old-disk",
                            "--from-sandbox", source, "--guest-flush", policy, "-o", str(archive))
                    assert not archive.exists()
                refused("legacy-pause-refuses", "pause", source, "--guest-flush", "required")
                refused("legacy-full-required-refuses", "snapshot", "create", "old-full-required",
                        "--from-sandbox", source, "--full", "--guest-flush", "required")
                refused("legacy-branch-skip-refuses", "branch", source, "--name", "must-not-branch",
                        "--guest-flush", "skip")
                run("legacy-full-auto-compatible", "snapshot", "create", "old-full",
                    "--from-sandbox", source, "--full")
                assert state(source) == "running"
                assert shell(source, "cat /dev/shm/flush-marker").stdout.strip() == "retained-ram"
                stop(source)
                # Reverse direction: an older CLI must still control a new runtime.
                source = "flush-current"
                names.append(source)
                run("create-current-for-old-cli", "create", "alpine", "--name", source,
                    "--memory", "256M", "--root-disk", "512M", "--max-duration", "30m")
                old = args.legacy_msb.resolve(strict=True)
                shell(source, "echo retained-ram > /dev/shm/flush-marker")
                run("old-cli-pauses-current", "pause", source, executable=old)
                # Old callers retain their crash-consistent disk cut while paused.
                run("old-cli-disk-current-paused", "snapshot", "create", "old-client-disk",
                    "--from-sandbox", source, executable=old)
                run("old-cli-full-current-paused", "snapshot", "create", "old-client-full",
                    "--from-sandbox", source, "--full", executable=old)
                assert state(source) == "paused"
                run("old-cli-resumes-current", "resume", source, executable=old)
                assert shell(source, "cat /dev/shm/flush-marker").stdout.strip() == "retained-ram"
                stop(source)
        completed = True
    finally:
        for name in reversed(names):
            try:
                stop(name)
            except Exception as error:
                rows.append({"case": "cleanup-" + name, "error": str(error)})
                completed = False
        try:
            remaining = json.loads(run("cleanup-status", "list", "--format", "json").stdout)
            assert all(item["status"].lower() not in ("running", "paused") for item in remaining), remaining
        except Exception:
            completed = False
            raise
        finally:
            save()
            print(report)


if __name__ == "__main__":
    main()
