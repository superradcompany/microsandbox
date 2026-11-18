#!/usr/bin/env python3
"""Exercise a running inner Linux VM through public snapshot and fork operations.

Requires a disposable MSB_HOME, MSB_PATH, NESTED_IMAGE, and NESTED_RESULTS.
The image contains the matching libkrun tests/nested-restore/os parent fixture,
plus /bin/sh and root passwd/group entries. See nested-snapshot.md.
"""

import json
import os
import platform
import subprocess
import time
import uuid
from pathlib import Path

assert os.environ.get("MSB_HOME"), "set a disposable MSB_HOME"
binary = os.environ["MSB_PATH"]
image = os.environ["NESTED_IMAGE"]
results = Path(os.environ["NESTED_RESULTS"])
results.mkdir(parents=True, exist_ok=True)
prefix = "nested-" + uuid.uuid4().hex[:10]
names = [
    prefix + suffix
    for suffix in ("-source", "-restored", "-a", "-b", "-second", "-archive")
]
source, restored, fork_a, fork_b, second, archived = names
sequence = 0
busy_mode = os.environ.get("NESTED_BUSY") == "1"


def run(*args, check=True):
    global sequence
    sequence += 1
    executable = binary
    environment = os.environ.copy()
    if args[0] == "run":
        executable = os.environ.get("NESTED_SOURCE_MSB_PATH", binary)
        environment["MSB_PATH"] = executable
        environment.update(json.loads(os.environ.get("NESTED_SOURCE_ENV", "{}")))
    result = subprocess.run(
        [executable, *map(str, args)],
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=180,
        check=False,
    )
    log = results / f"{sequence:04d}-{args[0]}"
    log.with_suffix(".out").write_bytes(result.stdout)
    log.with_suffix(".err").write_bytes(result.stderr)
    if check and result.returncode:
        raise RuntimeError(
            (args, result.returncode, result.stderr.decode(errors="replace"))
        )
    return result


def sample(name):
    result = run(
        "exec",
        name,
        "--",
        "/bin/busybox",
        "tail",
        "-n",
        "4",
        "/nested-progress.log",
        check=False,
    )
    # The producer may still be writing its final record.
    complete = result.stdout.rpartition(b"\n")[0]
    lines = complete.splitlines()
    for index in range(len(lines) - 1, -1, -1):
        line = lines[index]
        fields = line.split()
        if len(fields) == 5 and fields[0] == b"NESTED_PROGRESS":
            counter, timer, identity = map(int, fields[1:4])
            assert fields[4] == f"disk={counter}".encode(), line
            if busy_mode:
                if index == 0:
                    return None  # Wait for a complete busy/progress record pair.
                workers = lines[index - 1].split()
                assert len(workers) == 3 and workers[0] == b"NESTED_BUSY_PROGRESS", workers
                return counter, timer, identity, *map(int, workers[1:])
            return counter, timer, identity
    return None


def progressing(name, saved=None):
    deadline = time.monotonic() + 120
    first = previous = None
    started = changed = None
    while time.monotonic() < deadline:
        current = sample(name)
        now = time.monotonic()
        if current:
            if saved:
                assert current[2] == saved[2], (name, "cold reboot", saved, current)
                assert current[0] >= saved[0] and current[1] >= saved[1], (
                    name,
                    saved,
                    current,
                )
                if busy_mode:
                    assert all(a >= b for a, b in zip(current[3:], saved[3:])), (
                        name,
                        "busy worker restarted",
                        saved,
                        current,
                    )
            if first is None:
                first = previous = current
                started = changed = now
            assert current[2] == first[2], (name, "workload restarted", first, current)
            assert current[0] >= previous[0] and current[1] >= previous[1], (
                name,
                previous,
                current,
            )
            if busy_mode:
                assert all(a >= b for a, b in zip(current[3:], previous[3:])), (
                    name,
                    "busy worker counter decreased",
                    previous,
                    current,
                )
            workers_advanced = not busy_mode or all(
                a > b for a, b in zip(current[3:], previous[3:])
            )
            if current[0] > previous[0] and current[1] > previous[1] and workers_advanced:
                changed = now
            assert now - changed < 3, (name, "inner VM stopped progressing", current)
            previous = current
            if now - started >= 10 and current[0] > first[0] + 20:
                if os.environ.get("NESTED_CHECK_CLOCK_RATE") == "1":
                    ratio = (current[1] - first[1]) / 1000 / (now - started)
                    assert 0.8 <= ratio <= 1.2, (name, "guest clock rate", ratio)
                    print(name, "guest/host elapsed-time ratio", ratio, flush=True)
                state = json.loads(run("inspect", name, "--format", "json").stdout)
                assert state["config"]["resources"]["nested_virt"] is True, state
                assert state["status"] == "Running", state
                print(name, current, flush=True)
                return current
        time.sleep(0.3)
    raise RuntimeError((name, "no sustained inner VM progress"))


architecture = os.environ.get("NESTED_ARCH", platform.machine()).lower()
if architecture in ("arm64", "aarch64"):
    machine, console, block = "virt,gic-version=3", "ttyAMA0", "virtio-blk-device"
else:
    assert architecture in ("amd64", "x86_64"), architecture
    machine, console, block = "q35,kernel_irqchip=on", "ttyS0", "virtio-blk-pci"

kernel_args = f"console={console} rdinit=/init panic=-1 quiet"
if busy_mode:
    kernel_args += " NESTED_BUSY=1"
if extra_args := os.environ.get("NESTED_KERNEL_ARGS"):
    kernel_args += f" {extra_args}"

try:
    run(
        "run",
        "-d",
        "-n",
        source,
        "--nested-virt",
        "--root-disk",
        "1G",
        "--cpus",
        "2",
        "--memory",
        "1G",
        image,
        "--",
        "/qemu-system",
        "-accel",
        "kvm",
        "-machine",
        machine,
        "-cpu",
        "host",
        "-smp",
        "2",
        "-m",
        "256",
        "-nodefaults",
        "-no-user-config",
        "-display",
        "none",
        "-monitor",
        "none",
        "-serial",
        "file:/nested-progress.log",
        "-kernel",
        "/inner-kernel",
        "-initrd",
        "/inner-initramfs",
        "-append",
        kernel_args,
        "-drive",
        "file=/state.img,format=raw,if=none,id=state,cache=writeback",
        "-device",
        f"{block},drive=state",
    )
    before = progressing(source)
    if os.environ.get("NESTED_EXPECT_UNSUPPORTED") == "1":
        for command in [
            ("snapshot", "create", "refused", "--from-sandbox", source, "--full"),
            ("fork", source, "--name", fork_a),
        ]:
            result = run(*command, check=False)
            assert result.returncode, command
            assert (
                b"nested execution-state capture and restore are not supported"
                in result.stderr
            ), result.stderr
        progressing(source, before)
    else:
        run("snapshot", "create", "full", "--from-sandbox", source, "--full")
        run("snapshot", "restore", f"{source}:full", "--name", restored)
        progressing(restored, before)
        before_fork = progressing(source, before)
        run("fork", source, "--names", fork_a, fork_b)
        for name in (fork_a, fork_b):
            progressing(name, before_fork)
        before_second = progressing(fork_a, before_fork)
        run("snapshot", "create", "second", "--from-sandbox", fork_a, "--full")
        run("snapshot", "restore", f"{fork_a}:second", "--name", second)
        progressing(second, before_second)
        archive = results / "nested.msb"
        run("snapshot", "export", f"{source}:full", "--output", archive)
        run("snapshot", "restore", archive, "--name", archived)
        progressing(archived, before)
        progressing(source, before_fork)
    (results / "result.json").write_text(
        json.dumps(
            {
                "result": "pass",
                "source": source,
                "identity": before[2],
                "architecture": architecture,
                "kernel_args": kernel_args,
                "busy_workers": busy_mode,
            }
        )
    )
finally:
    for name in names:
        run("stop", "--force", name, check=False)
