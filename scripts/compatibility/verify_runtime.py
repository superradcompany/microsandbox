#!/usr/bin/env python3
"""Verify a live fixture VM runs the selected executable, not a bundled runtime."""

import hashlib
import json
import os
from pathlib import Path
import sys


def verify(home, expected_hash, sandbox, proc=Path("/proc")):
    matches = []
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            # Inspect only processes belonging to this fixture home. A matching
            # command name alone is never sufficient ownership evidence.
            environment = (entry / "environ").read_bytes().split(b"\0")
            if os.fsencode(f"MSB_HOME={home}") not in environment:
                continue
            args = (entry / "cmdline").read_bytes().split(b"\0")
            if len(args) < 2 or args[1] not in (b"machine", b"sandbox"):
                continue
            with (entry / "exe").open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            if digest != expected_hash:
                raise RuntimeError(f"fixture PID {entry.name} ran unexpected runtime {digest}")
            # Check every owned VM's executable before selecting the requested
            # name: a healthy control VM must not hide a missing target or a
            # different VM running the wrong binary in this same fixture home.
            names = [value for flag, value in zip(args, args[1:]) if flag == b"--name"]
            if names == [os.fsencode(sandbox)]:
                matches.append(dict(pid=int(entry.name), executable=str((entry / "exe").resolve()), sha256=digest))
        except (FileNotFoundError, ProcessLookupError):
            # Unrelated processes can exit while /proc is being enumerated.
            continue
        except PermissionError:
            # Other users' processes are not fixture ownership evidence.
            if entry.stat().st_uid == os.getuid():
                raise
    if not matches:
        raise RuntimeError(f"no live VM for sandbox {sandbox!r} observed in the fixture home")
    return matches


if __name__ == "__main__":
    record = dict(sandbox=sys.argv[1], runtimes=verify(os.environ["MSB_HOME"],
                  os.environ["MSB_COMPAT_RUNTIME_SHA256"], sys.argv[1]))
    with open(os.environ["MSB_COMPAT_RUNTIME_REPORT"], "a") as log:
        log.write(json.dumps(record) + "\n")
    print(json.dumps(record))
