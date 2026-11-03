#!/usr/bin/env python3
"""Qualify protected storage with real guest tampering and disk lifecycle operations.

Requires --binary and --output (a new, disposable directory). An optional --old-binary checks
catalog and launch refusals. Matching firmware is selected through MSB_LIBKRUNFW_PATH.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--old-binary", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--image", default="mirror.gcr.io/library/alpine:3.20")
    parser.add_argument("--disk-only", action="store_true", help="Exercise cold restores on hosts whose firmware cannot capture execution")
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    home = output / "home"
    env = dict(os.environ, MSB_HOME=str(home), MSB_PATH=str(binary), MSB_BACKEND="local", NO_COLOR="1")
    for key in ("MSB_CONFIG_PATH", "MSB_PROFILE"):
        env.pop(key, None)
    results = []
    names = ["protected", "restored", "refused"]

    def run(label, *command, executable=binary, override=None, refusal=None):
        result = subprocess.run([str(executable), *command], env=dict(env, **(override or {})),
                                cwd=output, capture_output=True, text=True, timeout=180)
        (output / f"{label}.stdout").write_text(result.stdout, encoding="utf-8")
        (output / f"{label}.stderr").write_text(result.stderr, encoding="utf-8")
        passed = result.returncode == 0 if refusal is None else (
            0 < result.returncode < 256 and refusal in result.stderr.lower())
        results.append(dict(case=label, passed=passed, exit=result.returncode))
        (output / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"{label}: {'PASS' if passed else 'FAIL'}", flush=True)
        assert passed, result.stdout + result.stderr
        return result.stdout

    def guest(label, script, name="protected"):
        return run(label, "exec", name, "--", "sh", "-ec", script)

    try:
        scripts = output / "scripts.json"
        scripts.write_text(json.dumps({"check.sh": "#!/bin/sh\nprintf script-ok\\n"}))
        run("create", "create", "--name", names[0], "--memory", "256M", "--root-disk", "256M",
            "--mount-owned", "/data:kind=disk,size=256M", "--script-conf", str(scripts), args.image)
        sandbox = home / "sandboxes" / names[0]
        canary = sandbox / "host-canary"
        canary.write_bytes(b"host-only canary\n")
        expected_canary = hashlib.sha256(canary.read_bytes()).hexdigest()
        assert (sandbox / "state-layout.json").is_file()
        assert (sandbox / "runtime/heartbeat.json").is_dir()
        guest("private-export", "test -d /.msb/scripts; test ! -e /.msb/root-disk.json; "
              "test ! -e /.msb/owned-disks; test ! -e /.msb/checkpoints; test ! -e /.msb/checkpoint-store")
        guest("seed", "echo root-data >/marker; echo volume-data >/data/marker; echo ram-data >/dev/shm/marker; sync")
        capture = run("clean-capture", "snapshot", "create", "clean-full", "--from-sandbox", names[0], *([] if args.disk_only else ["--full"]))
        snapshot = capture.strip().splitlines()[-1]
        assert "script-ok" in guest("script", "sh /.msb/scripts/check.sh")
        forged = json.loads((sandbox / "root-disk.json").read_text())
        forged["layers"][0]["path"] = str(canary)
        payload = shlex.quote(json.dumps(forged))
        guest("forge-guest-journals", f"printf '%s' {payload} >/.msb/root-disk.json; "
              "mkdir -p /.msb/owned-disks /.msb/checkpoints /.msb/checkpoint-store; "
              "echo forged >/.msb/checkpoints/guest-controlled")
        run("live-grow", "modify", names[0], "--root-disk", "320M")
        capture = run("capture", "snapshot", "create", "protected-full", "--from-sandbox", names[0], *([] if args.disk_only else ["--full"]))
        hostile_snapshot = capture.strip().splitlines()[-1]
        assert (sandbox / "checkpoints").is_dir()
        assert (sandbox / "checkpoint-store").is_dir()
        assert (sandbox / "owned-disks").is_dir()
        run("live-compact", "modify", names[0], "--compact")
        # Tampered guest files must never become host write destinations during the next boot.
        guest("leave-links", f"rm /.msb/scripts/check.sh; ln -s {shlex.quote(str(canary))} /.msb/scripts/check.sh; "
              f"rm -f /.msb/heartbeat.json; ln -s {shlex.quote(str(canary))} /.msb/heartbeat.json")
        run("stop", "stop", names[0])
        run("stopped-grow", "modify", names[0], "--root-disk", "384M")
        run("stopped-compact", "modify", names[0], "--compact")
        if args.old_binary:
            old = args.old_binary.resolve(strict=True)
            run("old-catalog-refusal", "list", executable=old, override={"MSB_PATH": str(old)}, refusal="database schema is newer")
            run("old-runtime-refusal", "start", names[0], override={"MSB_PATH": str(old)}, refusal="upgrade required")
        run("restart", "start", names[0])
        assert "script-ok" in guest("script-after-restart", "sh /.msb/scripts/check.sh")
        guest("data-after-restart", "test $(cat /marker) = root-data; test $(cat /data/marker) = volume-data; "
              "test ! -e /.msb/root-disk.json; test ! -e /.msb/checkpoints")
        run("restore", "restore", snapshot, "--name", names[1])
        guest("restored-data", "test $(cat /marker) = root-data; test $(cat /data/marker) = volume-data; "
              + ("true" if args.disk_only else "test $(cat /dev/shm/marker) = ram-data"), names[1])
        assert hashlib.sha256(canary.read_bytes()).hexdigest() == expected_canary
        # Guest-created retained handles must never be redirected into host journals on restore.
        if args.disk_only:
            run("hostile-disk-restore", "restore", hostile_snapshot, "--name", names[2])
            guest("hostile-disk-private-export", "test ! -e /.msb/root-disk.json; test ! -e /.msb/checkpoints", names[2])
        else:
            run("hostile-handle-restore", "restore", hostile_snapshot, "--name", names[2], refusal="failed to start")
        assert hashlib.sha256(canary.read_bytes()).hexdigest() == expected_canary
        for name in names[:2]:
            journal = json.loads((home / "sandboxes" / name / "root-disk.json").read_text())
            assert all(layer["path"] != str(canary) for layer in journal["layers"])
        print("Protected storage and host canary checks passed", flush=True)
    finally:
        for name in names:
            subprocess.run([str(binary), "stop", name, "--force"], env=env, cwd=output,
                           capture_output=True, timeout=30)


    if args.old_binary:
        # Upgrade the catalog while an actual old VM is still running. Storage must
        # refuse before migration, while exec/stop remain usable for a safe restart.
        env["MSB_HOME"] = str(output / "legacy-home")
        old = args.old_binary.resolve(strict=True)
        try:
            run("legacy-create", "create", "--name", names[0], "--memory", "256M", "--root-disk", "256M",
                args.image, executable=old, override={"MSB_PATH": str(old)})
            run("legacy-seed", "exec", names[0], "--", "sh", "-ec", "echo retained >/legacy-marker; sync",
                executable=old, override={"MSB_PATH": str(old)})
            run("upgrade-catalog", "list")
            legacy = output / "legacy-home/sandboxes" / names[0]
            before = (legacy / "runtime/root-disk.json").read_bytes() if (legacy / "runtime/root-disk.json").exists() else None
            for label, command in [
                ("full", ("snapshot", "create", "blocked-full", "--from-sandbox", names[0], "--full")),
                ("disk", ("snapshot", "create", "blocked-disk", "--from-sandbox", names[0])),
                ("branch", ("branch", names[0], "--name", names[2], "--dangerously-inherit-resources")),
                ("grow", ("modify", names[0], "--root-disk", "320M")),
                ("compact", ("modify", names[0], "--compact")),
            ]:
                run("legacy-storage-refusal-" + label, *command, refusal="stop and restart")
            assert not (legacy / "state-layout.json").exists()
            after = (legacy / "runtime/root-disk.json").read_bytes() if (legacy / "runtime/root-disk.json").exists() else None
            assert before == after
            guest("legacy-exec-remains-available", "test $(cat /legacy-marker) = retained")
            run("legacy-stop", "stop", names[0])
            run("legacy-migrate-restart", "start", names[0])
            guest("legacy-data-after-migration", "test $(cat /legacy-marker) = retained; test ! -e /.msb/root-disk.json")
            assert (legacy / "state-layout.json").is_file()
            assert (legacy / "runtime/heartbeat.json").is_dir()
            run("migrated-storage", "modify", names[0], "--root-disk", "320M")
        finally:
            for name in names:
                subprocess.run([str(binary), "stop", name, "--force"], env=env, cwd=output,
                               capture_output=True, timeout=30)


if __name__ == "__main__":
    main()
