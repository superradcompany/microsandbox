#!/usr/bin/env python3
"""Exercise storage ownership with real VMs in disposable, isolated homes."""

import argparse
import fcntl
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path


def run(args):
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    # Keep runtime sockets under sockaddr_un's limit, independent of the report path.
    root = Path(tempfile.mkdtemp(prefix="msb-sl-", dir="/tmp"))
    config = root / "config.json"
    config.write_text("{}")
    env = dict(os.environ, MSB_CONFIG_PATH=str(config), MSB_BACKEND="local", NO_COLOR="1",
               MSB_PATH=str(args.binary), MSB_AGENTD_PATH=str(args.agent),
               MSB_LIBKRUNFW_PATH=str(args.firmware))
    env.pop("MSB_PROFILE", None)
    records = []
    homes = [root / "source", root / "received"]

    def command(label, *words, home=homes[0], success=True):
        started = time.monotonic()
        result = subprocess.run([str(args.binary), *words], env=dict(env, MSB_HOME=str(home)),
                                cwd=root, text=True, capture_output=True, timeout=180, check=False)
        (output / f"{label}.log").write_text(result.stdout + result.stderr)
        records.append({"case": label, "code": result.returncode,
                        "seconds": round(time.monotonic() - started, 3)})
        (output / "results.json").write_text(json.dumps({"root": str(root), "cases": records}, indent=2) + "\n")
        assert (result.returncode == 0) == success, (label, result.stdout, result.stderr)
        print(label, "PASS", flush=True)
        return result

    def report(label, *words, **kwargs):
        return json.loads(command(label, *words, "--format", "json", **kwargs).stdout)

    try:
        command("create", "create", args.image, "--name", "source", "--memory", "256M",
                "--max-memory", "256M", "--cpus", "1", "--root-disk", "128M",
                "--tmpfs", "/ram:16M", "--no-net")
        command("write-state", "exec", "source", "--", "sh", "-ec",
                "printf disk-state > /root/storage-marker; printf ram-state > /ram/storage-marker")
        assert report("prune-running-image", "image", "prune", "--yes")["image_refs_removed"] == 0
        command("force-untag-running-image", "image", "rm", args.image, "--force")
        command("capture-full", "snapshot", "create", "base", "--group", "saved",
                "--sandbox", "source", "--full")
        snapshots = report("snapshot-list", "snapshot", "list")
        assert len(snapshots) == 1, snapshots
        # The descriptor lock is the public read-only admission primitive. Hold it from
        # a separate process while exercising the real CLI's forced deletion path.
        descriptor, = (homes[0] / "snapshots/saved").glob("*/snapshot.json")
        with descriptor.open("rb") as reader:
            fcntl.flock(reader, fcntl.LOCK_SH)
            busy = command("snapshot-reader-refuses-force", "snapshot", "rm", "saved:base", "--force", success=False)
            assert "active operation" in busy.stderr, busy.stderr
        archive = root / "saved.msb"
        command("portable-export", "snapshot", "export", "saved:base", "--with-image", "-o", str(archive))
        command("branch", "branch", "source", "--name", "branch", "--dangerously-inherit-resources")
        usage = report("usage-live", "df")
        assert usage["branch_memory"]["in_use"] > 0, usage
        report("prune-live-ram", "prune", "--yes")
        command("branch-retains-state", "exec", "branch", "--", "sh", "-ec",
                'test "$(cat /root/storage-marker)" = disk-state; test "$(cat /ram/storage-marker)" = ram-state')
        command("stop-source", "stop", "source")
        command("stop-branch", "stop", "branch")
        assert report("usage-after-stops", "df")["branch_memory"]["count"] == 0
        assert report("prune-stopped-image", "image", "prune", "--yes")["image_refs_removed"] == 0
        command("remove-source", "remove", "source")
        command("remove-branch", "remove", "branch")
        assert report("snapshot-roots-image", "image", "prune", "--yes")["image_refs_removed"] == 0
        report("reclaim-idle-ram", "prune", "--yes")
        assert report("usage-after-prune", "df")["branch_memory"]["count"] == 0
        command("restore-local", "restore", "saved:base", "--name", "restored", "--forked", "--no-net")
        command("restore-retains-state", "exec", "restored", "--", "sh", "-ec",
                'test "$(cat /root/storage-marker)" = disk-state; test "$(cat /ram/storage-marker)" = ram-state')
        command("import-fresh-home", "snapshot", "import", str(archive), "--group", "imported", home=homes[1])
        assert report("imported-snapshot-roots-image", "image", "prune", "--yes", home=homes[1])["image_refs_removed"] == 0
        command("restore-imported", "restore", "imported:base", "--name", "received", "--forked", "--no-net", home=homes[1])
        command("import-retains-state", "exec", "received", "--", "sh", "-ec",
                'test "$(cat /root/storage-marker)" = disk-state; test "$(cat /ram/storage-marker)" = ram-state', home=homes[1])
        for home, name, selector in [(homes[0], "restored", "saved:base"), (homes[1], "received", "imported:base")]:
            # Completed restores own their payloads. Deleting the source must succeed,
            # while the running child's catalog ownership still excludes its image from GC.
            command(f"remove-snapshot-{name}", "snapshot", "rm", selector, home=home)
            assert report(f"restored-vm-roots-image-{name}", "image", "prune", "--yes", home=home)["image_refs_removed"] == 0
            report(f"prune-while-restored-{name}", "prune", "--yes", home=home)
            command(f"independent-restored-state-{name}", "exec", name, "--", "sh", "-ec",
                    'test "$(cat /root/storage-marker)" = disk-state; test "$(cat /ram/storage-marker)" = ram-state', home=home)
            command(f"stop-{name}", "stop", name, home=home)
            command(f"remove-{name}", "remove", name, home=home)
            reclaimed = report(f"reclaim-image-{name}", "image", "prune", "--yes", home=home)
            # Resolution can add a canonical alias alongside the originally requested tag.
            assert reclaimed["image_refs_removed"] >= 1 and reclaimed["layers_removed"] == 1, reclaimed
            assert report(f"empty-images-{name}", "image", "list", home=home) == []
            report(f"reclaim-ram-{name}", "prune", "--yes", home=home)
        print("All live storage lifecycle checks passed. Reports:", output, flush=True)
    finally:
        # Only touch homes allocated above. Do not use historical bare PIDs for cleanup.
        failures = []
        for index, home in enumerate(homes):
            if not home.exists():
                continue
            try:
                for item in report(f"cleanup-list-{index}", "list", home=home):
                    if item["status"] not in ("Stopped", "Crashed"):
                        command(f"cleanup-stop-{index}-{item['name']}", "stop", item["name"], "--force", home=home)
            except Exception as error:  # noqa: BLE001 - clean every home, then report all failures.
                failures.append(str(error))
        if failures:
            raise RuntimeError(f"fixture cleanup failed in {root}: {failures}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--agent", type=Path, required=True)
    parser.add_argument("--firmware", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--image", default="alpine:3.20")
    args = parser.parse_args()
    for name in ("binary", "agent", "firmware"):
        setattr(args, name, getattr(args, name).resolve(strict=True))
    run(args)
