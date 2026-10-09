#!/usr/bin/env python3
"""Retained guest behavior across disk/full/archive restore and later cold starts.

Set MSB_PATH, MSB_LIBKRUNFW_PATH and RESTORE_GUEST_OUT (a new, short temp path).
MSB_TEST_IMAGE defaults to Alpine. Optional RESTORE_INIT_IMAGE also checks PID 1
handoff against a systemd image. Every sandbox is removed, including on failure.
"""

import json
import os
from pathlib import Path
import subprocess

binary = os.environ["MSB_PATH"]
root = Path(os.environ["RESTORE_GUEST_OUT"])
root.mkdir(parents=True, exist_ok=False)
env = dict(os.environ, MSB_HOME=str(root / "home"))
names = []
sequence = 0


def run(*args, fail=False):
    global sequence
    args = tuple(map(str, args))
    sequence += 1
    result = subprocess.run(
        [binary, *map(str, args)],
        env=env,
        input="",
        capture_output=True,
        text=True,
        timeout=240,
    )
    (root / f"{sequence:03}.json").write_text(
        json.dumps(
            {
                "args": args,
                "exit": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            },
            indent=2,
        )
    )
    print(
        f"{sequence:03} exit={result.returncode}: {' '.join(map(str, args[:5]))}",
        flush=True,
    )
    assert (result.returncode != 0) == fail, result.stderr[-4000:]
    return result


def child(name, snapshot, *args):
    names.append(name)
    run("snapshot", "restore", snapshot, "--name", name, *args)


def verify(name, ram=False):
    data = json.loads(run("inspect", name, "--format", "json").stdout)
    assert data.get("config"), data
    for key in ("config", "active_config"):
        config = data.get(key)
        if not config:
            continue
        assert config["security_profile"] == "restricted", config
        assert config["runtime"]["shell"] == "/bin/ash", config
        assert config["runtime"]["workdir"] == "/tmp", config
        assert config["resources"]["thp"] == "never", config
        assert any(Path(name).name == "hello" for name in config["runtime"]["scripts"]), config
        assert config["runtime"]["cmd"] == ["echo replayed > /command-replayed"], config
    run(
        "exec",
        "--no-tty",
        name,
        "--",
        "sh",
        "-ec",
        'test "$RETENTION_TEST" = retained; test "$PWD" = /tmp; '
        'test "$(hostname)" = retained-host; test "$(ulimit -n)" = 256; '
        'grep -q "NoNewPrivs:[[:space:]]*1" /proc/self/status; '
        'grep -q " /ram tmpfs .*size=16384k" /proc/mounts; '
        'grep -q " /zero tmpfs " /proc/mounts; '
        'test "$(cat /disk-marker)" = disk; test ! -e /command-replayed; '
        + ('test "$(cat /ram/marker)" = memory' if ram else "test ! -e /ram/marker"),
    )
    assert "script-retained" in run("exec", "--no-tty", name, "--", "hello").stdout


try:
    (root / "source.yaml").write_text(
        "rlimits:\n  - {resource: nofile, soft: 256, hard: 256}\n"
        'entrypoint: ["/bin/sh", "-c"]\ncmd: ["echo replayed > /command-replayed"]\n'
    )
    names.append("source")
    run(
        "create",
        os.environ.get("MSB_TEST_IMAGE", "alpine:3.22"),
        "--name",
        "source",
        "--conf",
        str(root / "source.yaml"),
        "--memory",
        "384M",
        "--cpus",
        "1",
        "--root-disk",
        "512M",
        "--env",
        "RETENTION_TEST=retained",
        "--workdir",
        "/tmp",
        "--shell",
        "/bin/ash",
        "--hostname",
        "retained-host",
        "--security",
        "restricted",
        "--thp",
        "never",
        "--tmpfs",
        "/ram:16M",
        "--script",
        "bin/hello=printf script-retained",
        "--tmpfs",
        "/zero:0",
    )
    run(
        "exec",
        "--no-tty",
        "source",
        "--",
        "sh",
        "-ec",
        "echo disk > /disk-marker; echo memory > /ram/marker",
    )
    # Execute the script before full capture: its runtime-owned backing must be recreated.
    verify("source", ram=True)
    run("modify", "source", "--next-start", "--workdir", "/")
    run("snapshot", "create", "disk", "--sandbox", "source")
    child("disk", "source:disk")
    verify("disk")
    run("snapshot", "create", "full", "--sandbox", "source", "--full")
    archive = str(root / "full.tar")
    run("snapshot", "save", "source:full", archive)
    run("snapshot", "create", "full-next", "--sandbox", "source", "--full")
    delta = str(root / "delta.tar")
    run("snapshot", "save", "source:full-next", delta, "--since", "source:full")
    names.append("branch")
    run("branch", "source", "--name", "branch")
    verify("branch", ram=True)
    run("stop", "branch")
    run("start", "branch")
    verify("branch")
    for name, snapshot, args, ram in [
        ("full", "source:full", [], True),
        ("archive", archive, [], True),
        ("forked", "source:full", ["--forked"], True),
        ("disk-only", "source:full", ["--disk-only"], False),
        ("archive-disk", archive, ["--disk-only"], False),
        ("delta", delta, ["--snapshot-base", "source:full"], True),
        ("delta-disk", delta, ["--snapshot-base", "source:full", "--disk-only"], False),
    ]:
        child(name, snapshot, *args)
        verify(name, ram)
        run("stop", name)
        run("start", name)
        verify(name)
    # Full restore cannot claim to replace the already-running captured PID 1.
    rejected = run(
        "snapshot",
        "restore",
        "source:full",
        "--name",
        "invalid-init",
        "--init",
        "auto",
        fail=True,
    )
    assert "init overrides require" in rejected.stderr, rejected.stderr
    # Cover stopped-source and direct archive capture, not only export of installed captures.
    run("modify", "source", "--next-start", "--workdir", "/tmp")
    run("stop", "source")
    disk_archive = str(root / "disk.tar")
    run("snapshot", "create", "--sandbox", "source", "--output", disk_archive)
    child("stopped-archive", disk_archive)
    verify("stopped-archive")
    if init_image := os.environ.get("RESTORE_INIT_IMAGE"):
        names.append("init-source")
        run(
            "create",
            init_image,
            "--name",
            "init-source",
            "--init",
            "auto",
            "--memory",
            "1G",
        )
        run("stop", "init-source")
        run("snapshot", "create", "ready", "--sandbox", "init-source")
        child("init-child", "init-source:ready")
        assert (
            "systemd"
            in run("exec", "--no-tty", "init-child", "--", "cat", "/proc/1/comm").stdout
        )
finally:
    for name in reversed(names):
        subprocess.run(
            [binary, "remove", "--force", name],
            env=env,
            input="",
            capture_output=True,
            text=True,
            timeout=90,
        )
