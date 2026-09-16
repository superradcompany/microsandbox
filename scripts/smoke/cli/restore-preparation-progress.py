#!/usr/bin/env python3
"""Hold a cache build lock beyond the old 180 s readiness limit (macOS/Linux).

Run checkpoint-memory-growth.py first, then pass its disposable cbh-*/home:
    python3 restore-preparation-progress.py MSB_BIN AGENTD LIBKRUNFW FIXTURE_HOME
Only this stopped fixture's sole RAM cache entry is moved aside, not deleted.
"""

import fcntl
import json
import os
from pathlib import Path
import pty
import struct
import subprocess
import sys
import termios
import threading
import time

binary, agent, firmware, home_arg = sys.argv[1:5]
home = Path(home_arg).resolve()
assert home.name == "home" and home.parent.name.startswith("cbh-"), "use a disposable checkpoint-memory-growth fixture"
locks = list((home / "cache/memory/snapshots").glob("*.build-lock"))
assert len(locks) == 1, "fixture must have exactly one snapshot backing"
cache = locks[0].with_suffix(".ram")
if cache.exists():
    with cache.open("rb") as backing:
        # Match cooperative eviction: never move an entry pinned by a live VM.
        fcntl.flock(backing, fcntl.LOCK_EX | fcntl.LOCK_NB)
        cache.rename(cache.with_suffix(f".previous-{time.time_ns()}"))
env = dict(os.environ, TERM="xterm-256color", MSB_HOME=str(home), MSB_PATH=binary,
           MSB_AGENTD_PATH=agent, MSB_LIBKRUNFW_PATH=firmware)
name = f"slow-progress-{os.getpid()}"
master, slave = pty.openpty()
fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 120, 0, 0))
chunks = []

def drain():
    while True:
        try:
            chunk = os.read(master, 16384)
            if not chunk:
                return
            chunks.append(chunk)
        except OSError:
            return

reader = threading.Thread(target=drain, daemon=True)
reader.start()
with locks[0].open("rb") as lock:
    fcntl.flock(lock, fcntl.LOCK_EX)
    started = time.monotonic()
    child = subprocess.Popen([binary, "create", "--name", name, "--from-snapshot", "checks:grown", "--forked"],
                             env=env, stdout=subprocess.PIPE, stderr=slave)
    os.close(slave)
    try:
        while time.monotonic() - started < 185 and child.poll() is None:
            time.sleep(0.25)
        assert child.poll() is None, "creation exited during preparation"
        fcntl.flock(lock, fcntl.LOCK_UN)
        stdout, _ = child.communicate(timeout=40)
        reader.join(2)
        terminal = b"".join(chunks).decode(errors="replace")
        assert child.returncode == 0, terminal
        checksum = subprocess.run([binary, "exec", name, "--", "sha256sum", "-c", "/work/hash"],
                                  env=env, capture_output=True, text=True, timeout=20)
        evidence = dict(seconds=time.monotonic()-started, code=child.returncode,
                        saw_wait="Waiting for RAM backing" in terminal, checksum=checksum.stdout,
                        checksum_code=checksum.returncode, terminal=terminal, stdout=stdout.decode())
        (home.parent / "slow-preparation.json").write_text(json.dumps(evidence, indent=2))
        assert evidence["saw_wait"] and checksum.returncode == 0, evidence
        print({key: value for key, value in evidence.items() if key != "terminal"}, flush=True)
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN)
        subprocess.run([binary, "stop", "--force", name], env=env, timeout=20)
        if child.poll() is None:
            child.terminate()
            child.wait(timeout=10)
        os.close(master)
