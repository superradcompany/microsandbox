#!/usr/bin/env python3
"""Live unavailable-resource checks. Uses an isolated home and cleans up only its own VMs.

Set MSB_PATH, MSB_AGENTD_PATH and MSB_LIBKRUNFW_PATH to matching development artifacts.
Optional RESOURCE_TEST_LAYOUT selects flat:512M (default) or 512M.
"""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

root = Path(tempfile.mkdtemp(prefix="msb-unavailable-", dir="/tmp" if os.name != "nt" else None))
env = dict(os.environ, MSB_HOME=str(root / "home"))
binary = env["MSB_PATH"]
names = []
rows = []
print(f"Evidence: {root}", flush=True)


def run(label, *args, fail=False, timeout=180):
    started = time.monotonic()
    result = subprocess.run([binary, *map(str, args)], env=env, input="",
                            text=True, capture_output=True, timeout=timeout)
    rows.append(dict(label=label, args=list(map(str, args)), code=result.returncode,
                     seconds=time.monotonic() - started, stdout=result.stdout, stderr=result.stderr))
    (root / "results.json").write_text(json.dumps(rows, indent=2))
    print(f"{label}: {result.returncode} ({rows[-1]['seconds']:.3f}s)", flush=True)
    assert (result.returncode != 0) == fail, result.stderr
    return result


def guest(name, script, fail=False):
    return run(name + "-exec", "exec", name, "--", "sh", "-ec", script, fail=fail)


try:
    workspace = (root / "workspace").resolve()
    workspace.mkdir()
    (workspace / "marker").write_text("host-original")
    for volume in ("one", "two"):
        run("volume-" + volume, "volume", "create", volume, "--kind", "disk", "--size", "128M")
    names.append("source")
    run("source", "create", "alpine", "--name", "source", "--memory", "256M",
        "--max-memory", "256M", "--root-disk", os.environ.get("RESOURCE_TEST_LAYOUT", "flat:512M"),
        "--mount-named", "one:/data:kind=disk,size=128M",
        "--mount-named", "two:/other:kind=disk,size=128M", "-v", f"{workspace}:/workspace")
    guest("source", "echo source > /data/marker; echo second > /other/marker; "
          "echo ram > /dev/shm/marker; sync")
    device = guest("source", "awk '$2==\"/other\" {print $1}' /proc/mounts").stdout.strip()
    assert device.startswith("/dev/"), device
    run("capture", "snapshot", "create", "saved", "--from-sandbox", "source", "--full")
    archive = root / "saved.msb"
    run("archive", "snapshot", "save", "source:saved", archive)
    for name, source, flags in [("eager", "source:saved", []),
                                ("forked", "source:saved", ["--forked"]),
                                ("archive-child", str(archive), ["--forked"]),
                                ("branch-child", None, [])]:
        names.append(name)
        if source is None:
            result = run(name, "branch", "source", "--name", name, "-v", "/data", "--quiet")
        else:
            result = run(name, "restore", source, "--name", name, "-v", "/data", "--quiet", *flags)
        assert "EIO" in result.stderr and "/other" in result.stderr, result.stderr
        guest(name, "test \"$(cat /dev/shm/marker)\" = ram; test \"$(cat /data/marker)\" = source")
        guest(name, f"ls -l {device}; cat /sys/block/{Path(device).name}/serial; cat /proc/mounts")
        guest(name, f"dd if={device} of=/dev/null bs=4096 skip=16384 count=1 iflag=direct", fail=True)
        guest(name, f"dd if=/dev/zero of={device} bs=512 count=1 oflag=direct", fail=True)
        guest(name, "touch /workspace/denied", fail=True)
        assert not (workspace / "denied").exists()
        guest(name, "echo child > /data/marker; sync /data")
        guest("source", "test \"$(cat /data/marker)\" = source; test \"$(cat /other/marker)\" = second")
        run(name + "-pause", "pause", name)
        run(name + "-resume", "resume", name)
        # Probe beyond the blocks retained in guest RAM; cached reads can still
        # succeed without issuing a request to the unavailable host device.
        guest(name, f"dd if={device} of=/dev/null bs=4096 skip=16384 count=1 iflag=direct", fail=True)
        run(name + "-stop", "stop", name, "--timeout", "10")
        run(name + "-remove", "remove", name)
        names.remove(name)
    print("PASS", flush=True)
finally:
    for name in reversed(names):
        result = subprocess.run([binary, "stop", name, "--timeout", "10"], env=env,
                                input="", capture_output=True, text=True, timeout=20)
        if result.returncode:
            subprocess.run([binary, "stop", name, "--force"], env=env, input="",
                           capture_output=True, text=True, timeout=20)
        subprocess.run([binary, "remove", name], env=env, input="", capture_output=True,
                       text=True, timeout=20)
