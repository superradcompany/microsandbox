#!/usr/bin/env python3
"""Check that refusing a live shrink preserves the job, guest, target and retained config."""

import argparse
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import subprocess
import time

from lifecycle_evidence import cleanup_sandbox, environment, install_termination_handler, smoke_home

# Touch all pages and keep the allocation until the host explicitly releases the job.
WORKLOAD = """
import os, pathlib, time
pages = bytearray(b'x') * (600 * 1024 * 1024)
pathlib.Path('/tmp/holding').write_text(str(os.getpid()))
while not pathlib.Path('/tmp/release').exists():
    time.sleep(.05)
assert pages[0] == pages[-1] == 120
"""


def qualify(candidate, previous, agent, firmware, home):
    env = environment(candidate, firmware, home, agent)
    env.update(TMPDIR=str(home), TMP=str(home), TEMP=str(home))

    def run(*args, cli=candidate, refusal=False):
        result = subprocess.run([cli, *args], env=env, cwd=home, stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, timeout=120)
        if refusal:
            if result.returncode == 0 or "refused before unplugging" not in result.stderr:
                raise RuntimeError(f"missing pressure refusal: {args!r}: {result.stderr}")
        elif result.returncode:
            raise RuntimeError(f"{args!r} exited {result.returncode}: {result.stderr}")
        return result.stdout.strip()

    def guest(*args):
        return run("exec", "load", "--", *args)

    def status():
        return json.loads(run("modify", "load", "--wait", "--timeout", "30",
                              "--format", "json"))["resize_status"]

    def configuration():
        with closing(sqlite3.connect(home / "db/msb.db")) as db:
            desired, = db.execute("SELECT config FROM sandbox WHERE name='load'").fetchone()
        return desired, (home / "sandboxes/load/last-active/state.json").read_bytes()

    with cleanup_sandbox(run, "load"):
        run("create", "--name", "load", "--cpus", "2", "--max-cpus", "4", "--memory", "512M",
            "--max-memory", "1536M", "python:3.12-alpine")
        run("modify", "load", "--memory", "1G", "--wait", "--timeout", "45")
        before = status()
        boot = guest("cat", "/proc/sys/kernel/random/boot_id")
        job = run("exec", "load", "-d", "--", "python", "-c", WORKLOAD)
        for _ in range(80):
            if guest("sh", "-c", "test -s /tmp/holding && echo ready || true") == "ready":
                break
            time.sleep(.1)
        else:
            raise RuntimeError("workload never reported its allocation")
        total = guest("cat", "/proc/meminfo").splitlines()[0]
        online = guest("cat", "/sys/devices/system/cpu/online")
        retained = configuration()
        clients = [(candidate, []), (candidate, ["--wait"]),
                   (candidate, ["--cpus", "3"]), (candidate, ["--cpus", "3", "--wait"])]
        if previous:
            clients.append((previous, []))
        for cli, flags in clients:
            run("modify", "load", "--memory", "512M", *flags, cli=cli, refusal=True)
            if configuration() != retained or status() != before:
                raise RuntimeError("refusal changed persisted configuration or resize status")
            if guest("cat", "/proc/sys/kernel/random/boot_id") != boot or guest("cat", "/proc/meminfo").splitlines()[0] != total:
                raise RuntimeError("refusal changed the boot identity or guest capacity")
            if guest("cat", "/sys/devices/system/cpu/online") != online:
                raise RuntimeError("pressure refusal changed online CPUs")
            guest("sh", "-ec", 'kill -0 "$(cat /tmp/holding)"')
        guest("touch", "/tmp/release")
        run("wait", "load", "--job", job, "--timeout", "15s")
        run("modify", "load", "--cpus", "3", "--memory", "512M", "--wait", "--timeout", "45")
        after = status()
        if {(item["actual"], item["state"]) for item in after} != {("3", "applied"), ("512 MiB", "applied")}:
            raise RuntimeError(f"shrink after release did not converge: {after}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("candidate", "agent", "firmware"):
        parser.add_argument("--" + flag, type=Path, required=True)
    parser.add_argument("--previous", type=Path, help="also exercise an older CLI with the candidate runtime")
    parser.add_argument("--temp-root", type=Path)
    args = parser.parse_args()
    install_termination_handler()
    with smoke_home("msp-", args.temp_root) as home:
        qualify(args.candidate.resolve(), args.previous.resolve() if args.previous else None,
                args.agent.resolve(), args.firmware.resolve(), home)
    print("Passed pressure refusal, workload and configuration preservation, and shrink after release.")
