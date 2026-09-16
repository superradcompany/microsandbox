#!/usr/bin/env python3
"""Run the historical catalog fixture with a verified, pinned Linux release."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request


VERSION = "0.6.18"
BUNDLE = "microsandbox-linux-x86_64.tar.gz"
FIRMWARE = "libkrunfw.so.5.6.1"
TEST = "backend::local::catalog::tests::live_sdk_preserves_historical_catalog_and_old_cli_reads_new_records"
RELEASE = f"https://github.com/superradcompany/microsandbox/releases/download/v{VERSION}"


def unpack_verified_release(archive, checksums, destination):
    """Verify before extraction; accept only the two expected regular files."""
    hashes = [line.split()[0] for line in checksums.splitlines()
              if len(line.split()) == 2 and line.split()[1].lstrip("*") == BUNDLE]
    with archive.open("rb") as source:
        actual = hashlib.file_digest(source, "sha256").hexdigest()
    if hashes != [actual]:
        raise ValueError("historical release checksum missing, duplicated, or mismatched")
    with tarfile.open(archive, "r:gz") as bundle:
        for name in ("msb", FIRMWARE):
            members = [member for member in bundle.getmembers() if member.name == name]
            if len(members) != 1 or not members[0].isfile():
                raise ValueError(f"expected one regular release file: {name}")
            # Never extract archive paths, symlinks, permissions or ownership.
            with bundle.extractfile(members[0]) as source, (destination / name).open("wb") as target:
                shutil.copyfileobj(source, target)
            (destination / name).chmod(0o700 if name == "msb" else 0o600)


def fixture_environment(root, artifacts):
    # Do not inherit a cloud backend, candidate Agentd, runtime, home or project
    # config. The old executable must use its own shipped guest payload.
    env = {key: value for key, value in os.environ.items() if not key.startswith("MSB_")}
    env.update(MSB_HOME=str(root / "home"), MSB_CATALOG_TEST_HOME=str(root / "home"),
               MSB_BACKEND="local", MSB_PATH=str(artifacts / "msb"),
               MSB_LIBKRUNFW_PATH=str(artifacts / FIRMWARE),
               MSB_CONFIG_PATH=str(root / "config.json"),
               LD_LIBRARY_PATH=str(artifacts), NO_COLOR="1")
    return env


def cleanup(env, root, log):
    """Clean only this runner's disposable catalog, including partial creates."""
    def msb(*args):
        result = subprocess.run([env["MSB_PATH"], *args], env=env, cwd=root,
                                capture_output=True, text=True, timeout=30, check=True)
        log.write(result.stdout + result.stderr)
        return result.stdout

    errors = []
    for sandbox in json.loads(msb("list", "--format", "json")):
        try:
            if sandbox["status"] not in ("Stopped", "Crashed"):
                msb("stop", sandbox["name"])
            msb("rm", sandbox["name"])
        except (subprocess.SubprocessError, OSError) as error:
            errors.append(str(error))
    remaining = json.loads(msb("list", "--format", "json"))
    if errors or remaining:
        raise RuntimeError(f"historical fixture cleanup failed: {errors}; remaining={remaining}")


def execute(args):
    archive = args.archive.resolve(strict=True)
    workspace = args.workspace.resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    # Short paths are important for historical Unix socket layouts. Keep failed
    # fixture data for diagnosis, rather than deleting disks beneath a live VM.
    root = Path(tempfile.mkdtemp(prefix="msb-ch-", dir="/tmp"))
    (root / "config.json").write_text("{}\n")
    with (output / "setup.log").open("w") as log:
        log.write(f"release={VERSION}\nfixture={root}\n")
        for name in (BUNDLE, "checksums.sha256"):
            request = urllib.request.Request(f"{RELEASE}/{name}", headers={"User-Agent": "msb-catalog-ci"})
            with urllib.request.urlopen(request, timeout=60) as source, (root / name).open("wb") as target:
                shutil.copyfileobj(source, target)
        unpack_verified_release(root / BUNDLE, (root / "checksums.sha256").read_text(), root)
    env = fixture_environment(root, root)
    try:
        with (output / "test.log").open("w") as log:
            # GNU timeout also signals the nextest process group, not just its
            # supervisor, so timed-out tests cannot keep creating VMs in cleanup.
            subprocess.run([
                "timeout", "--kill-after=10s", "180s", "cargo-nextest", "nextest", "run",
                "--archive-file", str(archive), "--workspace-remap", str(workspace),
                "--run-ignored=only", "-E", f"test(={TEST})", "--test-threads", "1",
            ], env=env, cwd=root, stdout=log, stderr=subprocess.STDOUT, check=True)
    finally:
        with (output / "cleanup.log").open("w") as log:
            cleanup(env, root, log)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    execute(parser.parse_args())
