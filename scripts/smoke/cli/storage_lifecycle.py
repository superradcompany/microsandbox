#!/usr/bin/env python3
"""Offline, process-level storage regressions. Uses only a fresh temporary MSB_HOME."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import io
import json
import os
import platform
import resource
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path


def add(archive: tarfile.TarFile, name: str, content: bytes) -> None:
    entry = tarfile.TarInfo(name)
    entry.size = len(content)
    entry.mode = 0o644
    archive.addfile(entry, io.BytesIO(content))


def fixture(path: Path, images: list[tuple[list[str], str, bytes]]) -> None:
    """Write distinct image configs while allowing aliases and shared layer contents."""
    manifest = []
    emitted = set()
    with tarfile.open(path, "w") as archive:
        for references, label, payload in images:
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode="w") as layer:
                add(layer, "hello.txt", payload)
            content = stream.getvalue()
            digest = hashlib.sha256(content).hexdigest()
            config = json.dumps({
                "architecture": "arm64" if platform.machine() in ("arm64", "aarch64") else "amd64",
                "os": "linux",
                "config": {"Env": [f"FIXTURE={label}"]},
                "rootfs": {"type": "layers", "diff_ids": [f"sha256:{digest}"]},
            }, separators=(",", ":")).encode()
            config_name = hashlib.sha256(config).hexdigest() + ".json"
            layer_name = f"{digest}/layer.tar"
            for name, data in ((config_name, config), (layer_name, content)):
                if name not in emitted:
                    add(archive, name, data)
                    emitted.add(name)
            manifest.append({"Config": config_name, "RepoTags": references, "Layers": [layer_name]})
        add(archive, "manifest.json", json.dumps(manifest).encode())


def limited() -> None:
    resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))


def wait_for(predicate, description: str) -> None:
    deadline = time.monotonic() + 15
    while not predicate():
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out waiting for {description}")
        time.sleep(0.01)


def busy(path: Path) -> bool:
    with path.open("a+b") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        return False


def lease_path(entry: Path) -> Path:
    return entry.parent / ".msb-leases" / (hashlib.sha256(os.fsencode(entry.name)).hexdigest() + ".lock")


def run(binary: Path, root: Path) -> None:
    config = root / "config.json"
    config.write_text("{}")
    env = dict(os.environ, MSB_CONFIG_PATH=str(config), MSB_BACKEND="local", NO_COLOR="1")
    env.pop("MSB_PROFILE", None)

    def command(home: Path, *args: str, low_fd: bool = False):
        result = subprocess.run([str(binary), *args], env=dict(env, MSB_HOME=str(home)),
                                text=True, capture_output=True, timeout=60, check=False,
                                preexec_fn=limited if low_fd else None)
        assert result.returncode == 0, (args, result.returncode, result.stdout, result.stderr)
        return result

    home = root / "bounded"
    archive = root / "eighty.tar"
    fixture(archive, [([f"example.invalid/image-{index}:latest"], str(index), b"shared") for index in range(80)])
    command(home, "image", "load", "-i", str(archive), low_fd=True)
    assert len(json.loads(command(home, "image", "ls", "--format", "json").stdout)) == 80
    report = json.loads(command(home, "image", "prune", "--yes", "--format", "json", low_fd=True).stdout)
    assert (report["image_refs_removed"], report["manifests_removed"], report["layers_removed"]) == (80, 80, 1), report
    print("PASS: 80-image import and prune under RLIMIT_NOFILE=256", flush=True)

    home = root / "aliases"
    fixture(archive, [(["audit-tiny:latest", "docker.io/library/audit-tiny:latest"], "alias", b"alias")])
    command(home, "image", "load", "-i", str(archive))
    report = json.loads(command(home, "image", "prune", "--yes", "--format", "json").stdout)
    assert report["image_refs_removed"] == 2 and report["skipped_in_use"] == 0, report
    assert json.loads(command(home, "image", "ls", "--format", "json").stdout) == []
    print("PASS: normalized aliases prune without a dangling reference", flush=True)

    home = root / "retag"
    a, gate, unrelated = [f"example.invalid/{name}:latest" for name in ("a", "gate", "unrelated")]
    fixture(archive, [([a], "old", b"OLD"), ([gate], "gate", b"GATE"), ([unrelated], "other", b"OTHER")])
    command(home, "image", "load", "-i", str(archive))
    manifests = home / "cache/manifests"
    a_path = manifests / (hashlib.sha256(a.encode()).hexdigest() + ".json")
    gate_path = manifests / (hashlib.sha256(gate.encode()).hexdigest() + ".json")
    assert a_path.is_file() and gate_path.is_file()
    lock_path = lease_path(gate_path)
    lock_path.parent.mkdir(exist_ok=True)
    out = root / "export.tar"
    with lock_path.open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        exporter = subprocess.Popen([str(binary), "image", "save", a, gate, "-o", str(out)],
                                    env=dict(env, MSB_HOME=str(home)), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            wait_for(lambda: busy(lease_path(a_path)), "export to select image A")
            # Export has selected A but cannot finish selecting its second image. Retag
            # and prune are separate real CLI processes, reproducing the original race.
            replacement = root / "replacement.tar"
            fixture(replacement, [([a], "new", b"NEW")])
            command(home, "image", "load", "-i", str(replacement))
            report = json.loads(command(home, "image", "prune", "--yes", "--format", "json").stdout)
            assert report["image_refs_removed"] == 1 and report["skipped_in_use"] > 0, report
            fcntl.flock(lock, fcntl.LOCK_UN)
            stdout, stderr = exporter.communicate(timeout=30)
            assert exporter.returncode == 0, (stdout, stderr)
        finally:
            if exporter.poll() is None:
                exporter.kill()
                exporter.wait()
    with tarfile.open(out) as exported:
        entries = json.load(exported.extractfile("manifest.json"))
        image = next(image for image in entries if a in image["RepoTags"])
        layer_bytes = exported.extractfile(image["Layers"][0]).read()
        with tarfile.open(fileobj=io.BytesIO(layer_bytes)) as layer:
            assert layer.extractfile("hello.txt").read() == b"OLD"
    print("PASS: retag and prune preserve the active export's original contents", flush=True)

    home = root / "accounting"
    command(home, "df", "--format", "json")
    journal = home / "cache/.image-deletions/delete-interrupted"
    journal.mkdir(parents=True)
    (journal / "0").write_bytes(b"x" * 1024 * 1024)
    usage = json.loads(command(home, "df", "--format", "json").stdout)
    assert usage["images"]["logical_bytes"] == 1024 * 1024, usage
    command(home, "image", "prune", "--yes")
    assert not journal.exists()
    print("PASS: df counts journal-only bytes and recovery disposes a missing-lock journal", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="msb-storage-regression-") as directory:
        run(args.binary.resolve(), Path(directory))


if __name__ == "__main__":
    main()
