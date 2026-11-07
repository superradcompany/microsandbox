#!/usr/bin/env python3
"""Check non-root guest device access and both security profiles in real VMs."""

import argparse
import ctypes
import errno
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--image", default="mirror.gcr.io/library/alpine")
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    args.output.mkdir(parents=True, exist_ok=False)
    home = Path(tempfile.mkdtemp(prefix="msb-dev-", dir="/tmp"))
    env = dict(os.environ)
    env.pop("MSB_PROFILE", None)
    env.update(MSB_HOME=str(home), MSB_CONFIG_PATH=str(home / "config.json"),
               MSB_BACKEND="local", MSB_PATH=str(binary))
    report = {"home": str(home), "commands": [], "failures": []}
    names = []

    def run(*arguments):
        command = [str(binary), *arguments]
        result = subprocess.run(command, env=env, capture_output=True, text=True,
                                timeout=120)
        report["commands"].append({"command": command, "exit": result.returncode,
                                   "stdout": result.stdout, "stderr": result.stderr})
        return result

    def check(condition, message):
        if not condition:
            report["failures"].append(message)

    try:
        for profile in ("default", "restricted"):
            name = "device-permissions-" + profile
            names.append(name)
            result = run("create", "--name", name, "--security", profile,
                         "--cpus", "1", "--memory", "256M", "--no-net",
                         "--max-duration", "2m", "--tmpfs", "/mnt/profile:1M",
                         args.image)
            if result.returncode:
                raise RuntimeError(result.stderr)
            prefix = ("exec", "--no-tty", "--no-stdin", "--timeout", "30s", name)
            result = run(*prefix, "--", "sh", "-c",
                         "awk '/^NoNewPrivs:|^CapEff:/{print}' /proc/self/status")
            if result.returncode:
                raise RuntimeError(result.stderr)
            status = dict(line.split() for line in result.stdout.splitlines())
            restricted = profile == "restricted"
            check(status["NoNewPrivs:"] == str(int(restricted)),
                  profile + ": wrong NoNewPrivs")
            check(bool(int(status["CapEff:"], 16) & (1 << 21)) != restricted,
                  profile + ": wrong CAP_SYS_ADMIN")
            result = run(*prefix, "--", "sh", "-c",
                         "awk '$2 == \"/mnt/profile\" {print $4}' /proc/mounts")
            flags = result.stdout.strip().split(",")
            check(result.returncode == 0 and all(
                (flag in flags) == restricted for flag in ("nosuid", "nodev")),
                profile + ": wrong user-mount flags")
            result = run(*prefix, "--", "sh", "-c",
                         "mkdir -p /mnt/probe && mount -t tmpfs tmpfs /mnt/probe "
                         "&& umount /mnt/probe")
            check((result.returncode == 0) != restricted,
                  profile + ": wrong mount permission")
            for device in ("/dev/fuse", "/dev/net/tun"):
                result = run(*prefix, "--", "stat", "-c", "%a %u %g", device)
                check(result.returncode == 0 and result.stdout.strip() == "666 0 0",
                      profile + ": wrong mode or owner for " + device)
                result = run("exec", "--no-tty", "--no-stdin", "--timeout", "30s",
                             "--user", "1000:1000", name, "--", "sh", "-c",
                             'test "$(id -u)" = 1000 && test -c "$1" && exec 3<>"$1"',
                             "sh", device)
                check(result.returncode == 0,
                      profile + ": UID 1000 cannot open " + device)
    finally:
        report["cleanup_ok"] = False
        try:
            removed = []
            for name in names:
                try:
                    result = run("rm", "--force", name)
                    removed.append(result.returncode == 0)
                    check(result.returncode == 0, "cannot remove sandbox " + name)
                except (subprocess.TimeoutExpired, OSError) as error:
                    removed.append(False)
                    report["failures"].append(f"cannot remove sandbox {name}: {error}")
            report["cleanup_ok"] = all(removed)
            if report["cleanup_ok"]:
                # Match metrics_registry_shm_name (ABI 3); the registry outlives the VM.
                home_hash = 0xcbf29ce484222325
                for byte in os.fsencode(home):
                    home_hash = ((home_hash ^ byte) * 0x100000001b3) & 0xffffffffffffffff
                registry = f"/msb-met-{home_hash:016x}-v3"
                libc = ctypes.CDLL(None, use_errno=True)
                result = libc.shm_unlink(ctypes.c_char_p(registry.encode()))
                check(result == 0 or ctypes.get_errno() == errno.ENOENT,
                      "cannot remove metrics registry " + registry)
                shutil.rmtree(home)
        finally:
            (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    if report["failures"] or not report["cleanup_ok"]:
        raise SystemExit("\n".join(report["failures"]) or "sandbox cleanup failed")
    print("Both profiles passed device access and security checks.")


if __name__ == "__main__":
    main()
