#!/usr/bin/env python3
"""Exercise the snapshot disk editor through create/run against live Linux guests."""

import argparse
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import time


def qualify(binary, firmware, image, layout, directory, full, legacy_cli):
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
        # An invalid guest workdir is checked after launch. It exercises recovery
        # after stopping the old VM, unlike the child-edit failure above.
        with sqlite3.connect((directory / "home/db/msb.db").as_uri() + "?mode=ro", uri=True) as catalog:
            row = "SELECT id, status FROM sandbox WHERE name='destination'"
            original_id, _ = catalog.execute(row).fetchone()
            for command in ("create", "run"):
                if command == "run":
                    msb("stop", "destination")
                invocation = ["--", "true"] if command == "run" else []
                result = msb(command, "--replace", "--name", "destination",
                             "--workdir", "/missing-after-boot", "--from-snapshot", "history",
                             *invocation, success=False)
                assert "/missing-after-boot" in result.stderr, result.stderr
                recovered = catalog.execute(row).fetchone()
                assert recovered == (original_id, "Stopped"), (original_id, recovered, result.stderr)
                assert "msb start destination" in result.stderr, result.stderr
                msb("start", "destination")
                assert guest("destination", "grep -qx keep /sentinel; cat /proc/sys/kernel/random/boot_id") != sentinel
            # Kill a separate CLI after it has reserved the replacement. The guest
            # may or may not have launched. A fresh client must handle both states.
            proc = subprocess.Popen([str(binary), "create", "--replace", "--name", "destination",
                                     "--workdir", "/missing-after-boot", "--from-snapshot", "history"],
                                    env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                deadline = time.monotonic() + 45
                while time.monotonic() < deadline:
                    pending = catalog.execute(
                        "SELECT candidate FROM sandbox_replacement WHERE name='destination'").fetchone()
                    if pending and pending[0] is not None:
                        break
                    assert proc.poll() is None, proc.communicate()
                    time.sleep(0.005)
                else:
                    raise AssertionError("replacement never reserved the candidate")
                proc.kill()
            finally:
                if proc.poll() is None:
                    proc.kill()
                proc.communicate(timeout=30)
            if legacy_cli:
                listing = subprocess.run([str(legacy_cli), "list"], env=env, capture_output=True,
                                         text=True, timeout=45, check=True)
                assert "source" in listing.stdout, listing
                removal = subprocess.run([str(legacy_cli), "rm", f".msb-retained-{original_id}"],
                                         env=env, capture_output=True, text=True, timeout=45)
                assert removal.returncode != 0, "released CLI deleted the retained original"
            msb("inspect", "destination")
            assert catalog.execute(row).fetchone() == (original_id, "Stopped")
            msb("start", "destination")
            guest("destination", "grep -qx keep /sentinel")
            if layout == "managed":
                # Unnamed detached runs are ephemeral. The stopped original must
                # survive maintenance, then regain automatic cleanup on restart.
                msb("run", "--detach", image, "--", "sh", "-c", "exec sleep 300")
                ephemeral_id, ephemeral_name = catalog.execute(
                    "SELECT id, name FROM sandbox WHERE ephemeral=1 AND status='Running'").fetchone()
                msb("create", "--replace", "--name", ephemeral_name, "--workdir", "/missing-after-boot",
                    "--from-snapshot", "history", success=False)
                ephemeral_row = "SELECT status, ephemeral FROM sandbox WHERE id=?"
                assert catalog.execute(ephemeral_row, (ephemeral_id,)).fetchone() == ("Stopped", 0)
                msb("start", ephemeral_name)
                assert catalog.execute(ephemeral_row, (ephemeral_id,)).fetchone() == ("Running", 1)
                msb("stop", ephemeral_name)
                deadline = time.monotonic() + 15
                while catalog.execute(ephemeral_row, (ephemeral_id,)).fetchone() is not None:
                    assert time.monotonic() < deadline, "restarted ephemeral sandbox was not removed"
                    time.sleep(0.1)
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
    parser.add_argument("--legacy-cli", type=Path, help="released CLI used to check catalog readability during recovery")
    args = parser.parse_args()
    for root_layout in ["managed", "flat"]:
        with tempfile.TemporaryDirectory(prefix="ed-", dir=args.temp_root) as scratch:
            qualify(args.binary.resolve(), args.firmware.resolve(), args.image,
                    root_layout, Path(scratch).resolve(), args.full, args.legacy_cli)
        print(f"PASS {root_layout}", flush=True)
