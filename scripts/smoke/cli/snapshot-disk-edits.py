#!/usr/bin/env python3
"""Exercise the snapshot disk editor through create/run against live Linux guests."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile


def qualify(binary, firmware, image, layout, directory, full):
    env = dict(os.environ, MSB_PATH=str(binary), MSB_LIBKRUNFW_PATH=str(firmware),
               MSB_HOME=str(directory / "home"))
    env.pop("MSB_AGENTD_PATH", None)

    def msb(*args, success=True):
        result = subprocess.run([str(binary), *map(str, args)], env=env, text=True,
                                capture_output=True, timeout=240)
        if (result.returncode == 0) != success:
            raise RuntimeError(f"{args!r} exited {result.returncode}\n{result.stdout}{result.stderr}")
        return result

    def guest(name, script):
        return msb("exec", name, "--", "sh", "-ec", script).stdout

    files = directory / "inputs"
    files.mkdir()
    (files / "binary").write_bytes(bytes([0, 1, 2, 255]))
    edits = [
        {"text": {"path": "/etc/app.conf", "content": "edited", "replace": True}},
        {"append": {"path": "/etc/alpine-release", "content": "child-only"}},
        {"mkdir": {"path": "/data/private", "mode": "0700"}},
        {"copy_dir": {"src": str(files), "dst": "/data/tree", "replace": True}},
        {"copy_file": {"src": str(files / "binary"), "dst": "/data/blob", "mode": "0600"}},
        {"symlink": {"target": "/etc/app.conf", "link": "/app-link"}},
        {"remove": {"path": "/etc/issue"}},
    ]
    good = directory / "good.json"
    bad = directory / "bad.json"
    good.write_text(json.dumps({"patches": edits}))
    bad.write_text(json.dumps({"patches": [edits[0], {"append": {"path": "/missing", "content": "x"}}]}))
    archive = directory / "original.msb"
    check = ('test "$(cat /db)" = captured; test "$(cat /app-link)" = edited; '
             'grep -q child-only /etc/alpine-release; test ! -e /etc/issue; '
             'cmp /data/tree/binary /data/blob; test "$(stat -c %a /data/blob)" = 600; '
             'test "$(stat -c %a /data/private)" = 700')
    try:
        msb("create", "--name", "source", "--root-disk",
            "256M" if layout == "managed" else "flat:256M", image)
        guest("source", "echo captured > /db; echo original > /etc/app.conf; mkdir -p /data; "
              "touch /data/tree; echo microsandbox-private-disk-editor/1 > /result; sync")
        msb("snapshot", "create", "history", "--sandbox", "source", "--integrity")
        msb("snapshot", "create", "--sandbox", "source", "--output", archive)
        msb("create", "--name", "destination", image)
        sentinel = guest("destination", "echo keep >/sentinel; cat /proc/sys/kernel/random/boot_id")
        result = msb("create", "--replace", "--name", "destination", "--fs-conf", bad,
                     "--from-snapshot", "history", success=False)
        assert "/missing" in result.stderr and "edit 2" in result.stderr, result.stderr
        assert guest("destination", "grep -q keep /sentinel; cat /proc/sys/kernel/random/boot_id") == sentinel
        msb("create", "--replace", "--name", "destination", "--fs-conf", good, "--from-snapshot", "history")
        guest("destination", check)
        msb("stop", "destination")
        msb("start", "destination")
        guest("destination", check)
        msb("run", "--fs-conf", good, "--from-snapshot", archive, "--", "sh", "-ec", check)
        msb("run", "--from-snapshot", "history", "--", "sh", "-ec",
            'test "$(cat /etc/app.conf)" = original; test "$(cat /db)" = captured; '
            'test -e /etc/issue; test ! -e /data/blob')
        msb("snapshot", "verify", "history")
        if full:
            msb("snapshot", "create", "full", "--sandbox", "source", "--full")
            before = guest("destination", "cat /proc/sys/kernel/random/boot_id")
            result = msb("create", "--replace", "--name", "destination", "--fs-conf", good,
                         "--from-snapshot", "full", success=False)
            assert "disk-only" in result.stderr or "full snapshot restore" in result.stderr, result.stderr
            assert guest("destination", "cat /proc/sys/kernel/random/boot_id") == before
            msb("run", "--disk-only", "--fs-conf", good, "--from-snapshot", "full", "--", "sh", "-ec", check)
    finally:
        for name in ["destination", "source"]:
            subprocess.run([str(binary), "stop", name], env=env, capture_output=True, timeout=60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("firmware", type=Path)
    parser.add_argument("--image", default="alpine:3.22")
    parser.add_argument("--temp-root", type=Path, default=Path("/tmp") if os.name == "posix" else None,
                        help="short path for the temporary runtime sockets")
    parser.add_argument("--full", action="store_true", help="also exercise a full checkpoint and disk-only boot")
    args = parser.parse_args()
    for root_layout in ["managed", "flat"]:
        with tempfile.TemporaryDirectory(prefix="ed-", dir=args.temp_root) as scratch:
            qualify(args.binary.resolve(), args.firmware.resolve(), args.image,
                    root_layout, Path(scratch).resolve(), args.full)
        print(f"PASS {root_layout}", flush=True)
