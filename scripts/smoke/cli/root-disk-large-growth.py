#!/usr/bin/env python3
"""One-shot root growth across GiB/metadata boundaries in an isolated MSB_HOME.

Uses the existing release binary, not a build step. QUAL_PREFIX must be fresh. Each
case stops its own VMs, keeps artifacts for inspection, and records failed checks.
"""

import hashlib
import itertools
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time


BINARY = os.environ["MSB_BIN"]
TEST_HOME = Path(os.environ["MSB_HOME"])
REPORT = Path(os.environ["QUAL_ROOT"])
PREFIX = os.environ["QUAL_PREFIX"]
MIB = 1048576
RESULTS = []
REPORT.mkdir(parents=True, exist_ok=True)


def record(label, passed, **details):
    RESULTS.append(dict(case=label, passed=passed, **details))
    (REPORT / "results.json").write_text(json.dumps(RESULTS, indent=2))
    print(f"{label}: {'PASS' if passed else 'FAIL'} {details}", flush=True)


def check(label, condition, **details):
    record(label, bool(condition), **details)
    if not condition:
        raise AssertionError(label)


def run(label, *args, refuse=False):
    started = time.perf_counter()
    result = subprocess.run([BINARY, *args], capture_output=True, text=True, timeout=300)
    elapsed = (time.perf_counter() - started) * 1000
    (REPORT / f"{label}.stdout").write_text(result.stdout)
    (REPORT / f"{label}.stderr").write_text(result.stderr)
    passed = result.returncode != 0 if refuse else result.returncode == 0
    record(label, passed, elapsed_ms=round(elapsed, 3), returncode=result.returncode)
    if not passed:
        raise AssertionError(result.stdout + result.stderr)
    return result.stdout


def guest(label, name, script):
    # A failed checksum must not be hidden by a later successful df/sync command.
    return run(label, "exec", name, "--", "sh", "-ec", script)


def state(name):
    return json.loads((TEST_HOME / "sandboxes" / name / "runtime" / "root-disk.json").read_text())


def capacity(layer):
    path = Path(layer["path"])
    with path.open("rb") as stream:
        magic = stream.read(4)
        if magic == b"QFI\xfb":
            stream.seek(24)
            return int.from_bytes(stream.read(8), "big")
    return path.stat().st_size


def digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(MIB), b""):
            result.update(block)
    return result.hexdigest()


def case(layout, backing, mode, target):
    label = f"{layout}-{backing}-{mode}-{target}"
    name = f"{PREFIX}-{label}"
    names = [name]
    try:
        disk = "512M" if layout == "managed" else "flat:512M"
        run(label + "-create", "create", "-n", name, "--root-disk", disk,
            "-m", "256M", "--max-duration", "30m", "alpine")
        guest(label + "-seed", name,
              "dd if=/dev/urandom of=/payload bs=1048576 count=8; "
              "sha256sum /payload >/expected; echo retained >/dev/shm/grow-marker; "
              "cat /proc/sys/kernel/random/boot_id >/boot-before; sync")
        if backing == "qcow2":
            run(label + "-old-snapshot", "snapshot", "create", name + "-old",
                "--from-sandbox", name, "--full")
        before = state(name)
        check(label + "-initial-capacity", capacity(before["layers"][-1]) == 512 * MIB)
        check(label + "-initial-format",
              before["layers"][-1]["format"] == ("qcow2" if backing == "qcow2" else "raw"))
        ancestors = [(layer["path"], digest(layer["path"])) for layer in before["layers"][:-1]]
        if mode == "stopped":
            run(label + "-stop-before-grow", "stop", name)
        # Time the first real CLI growth, including planning, control and configuration persistence.
        size = "4G" if target == 4096 else f"{target}M"
        run(label + "-grow", "modify", name, "--root-disk", size, "--format", "json")
        after = state(name)
        check(label + "-exact-capacity", capacity(after["layers"][-1]) == target * MIB)
        check(label + "-depth-and-completion", len(after["layers"]) == len(before["layers"])
              and after.get("growth_target") is None)
        check(label + "-immutable-ancestors", all(digest(path) == old for path, old in ancestors))
        # The public CLI deliberately rejects an already configured size. Runtime forward
        # recovery is repeatable, but that is distinct from a redundant completed CLI request.
        repeated = run(label + "-same-target", "modify", name, "--root-disk", size,
                       "--format", "json", refuse=True)
        check(label + "-same-target-reason", "only grow is supported" in repeated)
        run(label + "-shrink-rejected", "modify", name, "--root-disk", "512M", refuse=True)
        check(label + "-refusal-keeps-capacity", capacity(state(name)["layers"][-1]) == target * MIB)
        if mode == "stopped":
            run(label + "-start-after-grow", "start", name)
            guest(label + "-ram-seed", name, "echo retained >/dev/shm/grow-marker")
        else:
            guest(label + "-no-reboot", name,
                  "test $(cat /proc/sys/kernel/random/boot_id) = $(cat /boot-before); "
                  "test $(cat /dev/shm/grow-marker) = retained")
        # Allocate (not merely truncate/seek) 3 GiB at the main target, using repeated random
        # bytes. Smaller allocation in metadata-boundary cases keeps the matrix practical.
        count = 384 if target == 4096 else 96
        allocated = count * 8 * MIB
        guest(label + "-write-added-space", name,
              f"i=0; while test $i -lt {count}; do cat /payload >>/large; i=$((i+1)); done; "
              f"test $(stat -c %s /large) = {allocated}; "
              f"test $(stat -c %b /large) -ge {allocated // 512}; "
              "sync; sha256sum /large >/large.expected; sha256sum -c /expected; "
              f"dd if=/payload of=/far bs=1048576 seek={target - 256} conv=fsync; "
              f"dd if=/far bs=1048576 skip={target - 256} count=8 2>/dev/null | cmp - /payload; "
              "df -k /; du -k /large")
        # Snapshot the allocated file, not just metadata or an empty resized filesystem.
        run(label + "-new-snapshot", "snapshot", "create", name + "-new", "--from-sandbox", name, "--full")
        run(label + "-source-stop", "stop", name)
        for suffix, expected in [("new", target)] + ([("old", 512)] if backing == "qcow2" else []):
            child = name + "-" + suffix + "-child"
            names.append(child)
            run(label + "-" + suffix + "-restore", "create", "-n", child, "--from-snapshot", name + "-" + suffix)
            check(label + "-" + suffix + "-restored-capacity", capacity(state(child)["layers"][-1]) == expected * MIB)
            script = "sha256sum -c /expected; test $(cat /dev/shm/grow-marker) = retained; "
            if suffix == "new":
                script += ("sha256sum -c /large.expected; "
                           f"dd if=/far bs=1048576 skip={target - 256} count=8 2>/dev/null | cmp - /payload")
            else:
                script += "test ! -e /large; test ! -e /far"
            guest(label + "-" + suffix + "-restored-data", child, script)
            run(label + "-" + suffix + "-child-stop", "stop", child)
        # Verify a cold boot after full capture as well as restoring captured memory.
        run(label + "-cold-start", "start", name)
        guest(label + "-cold-data", name, "sha256sum -c /expected; sha256sum -c /large.expected")
        run(label + "-cold-stop", "stop", name)
    finally:
        for owned in names:
            result = subprocess.run([BINARY, "stop", owned], capture_output=True, text=True, timeout=40)
            if result.returncode:
                print(f"Cleanup needs inspection: {owned}: {result.stderr}", flush=True)


def offline_check(layout, backing, mode, target):
    """Independently check a disposable flattened copy, never repair the source chain."""
    label = f"{layout}-{backing}-{mode}-{target}"
    name = f"{PREFIX}-{label}"
    statuses = json.loads(run(label + "-list-for-fsck", "list", "--format", "json"))
    check(label + "-stopped-for-fsck", any(item["name"] == name and item["status"] == "Stopped" for item in statuses))
    head = state(name)["layers"][-1]["path"]
    qemu = os.environ.get("QEMU_IMG", "qemu-img")
    fsck = os.environ["E2FSCK"]

    def external(suffix, args):
        started = time.perf_counter()
        result = subprocess.run(args, capture_output=True, text=True, timeout=300)
        (REPORT / f"{label}-{suffix}.stdout").write_text(result.stdout)
        (REPORT / f"{label}-{suffix}.stderr").write_text(result.stderr)
        check(label + "-" + suffix, result.returncode == 0,
              elapsed_ms=round((time.perf_counter() - started) * 1000, 3),
              returncode=result.returncode)

    external("qemu-chain", [qemu, "info", "--backing-chain", "--output=json", head])
    # The only automatically removed files belong to this newly created scratch directory.
    with tempfile.TemporaryDirectory(prefix="growth-fsck-") as scratch:
        disk = str(Path(scratch) / "check.raw")
        external("flatten-for-check", [qemu, "convert", "-O", "raw", head, disk])
        # A stopped guest can leave a replayable journal. Replay only on the disposable copy,
        # then require a read-only full filesystem check with no corrective repairs.
        external("journal-replay", [fsck, "-p", "-E", "journal_only", disk])
        external("fsck", [fsck, "-f", "-n", disk])


def main():
    # 8 GiB occupies 64 groups; 8320 MiB needs a second 64-byte-descriptor GDT block.
    targets = [int(value) for value in os.environ.get("QUAL_TARGETS", "4096,8320").split(",")]
    failures = []
    for target, layout, backing, mode in itertools.product(
            targets, ("managed", "flat"), ("raw", "qcow2"), ("live", "stopped")):
        try:
            if os.environ.get("QUAL_OFFLINE_ONLY") == "1":
                offline_check(layout, backing, mode, target)
            else:
                case(layout, backing, mode, target)
        except Exception as error:
            label = f"{layout}-{backing}-{mode}-{target}"
            record(label + "-exception", False, error=str(error))
            failures.append(label)
    if failures:
        raise SystemExit("Failed cases: " + ", ".join(failures))
    print(f"All {len(targets) * 8} large-jump scenarios passed", flush=True)


if __name__ == "__main__":
    main()
