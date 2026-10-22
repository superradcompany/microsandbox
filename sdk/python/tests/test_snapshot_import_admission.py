"""Real native imports keep call-time paths and backend through deferred execution."""

import asyncio
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def test_deferred_import_admission() -> None:
    # Cwd/backend changes cannot leak into other tests or rely on scheduling luck
    # from a shared pytest event loop. The child uses the real native extension.
    result = subprocess.run(
        [sys.executable, str(Path(__file__).resolve())],
        capture_output=True,
        text=True,
        timeout=90,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PYTHON_IMPORT_ADMISSION_OK" in result.stdout


async def exercise(root: Path) -> None:
    os.environ["MSB_HOME"] = str(root / "home-a")
    os.environ["MSB_CONFIG_PATH"] = str(root / "absent.json")
    from microsandbox import BackendKind, Checkpoint, Snapshot, set_default_backend

    first, second = root / "first", root / "second"
    source = first / "source"
    source.mkdir(parents=True)
    second.mkdir()
    manifest = {
        "schema": 1,
        "artifact": "snapshot",
        "scope": "disk",
        "created_at": "2026-05-01T12:00:00Z",
        "parent": None,
        "image": {"ref": "docker.io/library/alpine:3.20", "manifest_digest": "sha256:" + "a" * 64},
        "source_sandbox": None,
        "state": {
            "kind": "file",
            "format": "raw",
            "fstype": "ext4",
            "upper": {"file": "upper.ext4", "size_bytes": 512, "integrity": None},
        },
        "labels": {},
        "extensions": {},
        "requires": [],
    }
    (source / "snapshot.json").write_text(json.dumps(manifest))
    (source / "upper.ext4").write_bytes(b"*" * 512)
    for name in ["base.tar", "delta.tar", "base-group"]:
        (second / name).write_text("unrelated shadow")
    os.chdir(first)
    set_default_backend(BackendKind.LOCAL)
    checkpoint = await Checkpoint.open(str(source))
    await checkpoint.save_to(str(first / "base.tar"), plain_tar=True)
    await checkpoint.save_to(
        str(first / "delta.tar"), plain_tar=True, since=str(first / "base.tar")
    )
    await Snapshot.load("base-group", ["base.tar"])

    # Every iteration restores the intended backend, calls an import, and immediately
    # changes both ambient inputs before awaiting it. Incremental imports must actually
    # resolve the base; testing standalone archives alone would miss reclassification.
    for index in range(12):
        os.chdir(first)
        os.environ["MSB_HOME"] = str(root / "home-a")
        set_default_backend(BackendKind.LOCAL)
        base = ["base-group", "base.tar", "./base.tar"][index % 3]
        kwargs = {"dest": "destination", "base": base}
        if index % 3 == 0:
            future = Snapshot.load(f"group-{index}", ["delta.tar"], **kwargs)
        elif index % 3 == 1:
            future = Checkpoint.load("delta.tar", group=f"group-{index}", **kwargs)
        else:
            future = Checkpoint.load_many(["delta.tar"], group=f"group-{index}", **kwargs)
        os.chdir(second)
        os.environ["MSB_HOME"] = str(root / "home-b")
        set_default_backend(BackendKind.LOCAL)
        result = await future
        handles = result.checkpoints if index % 3 == 0 else [result] if index % 3 == 1 else result
        assert len(handles) == 1
        handle = handles[0]
        assert Path(handle.path).is_relative_to(first / "destination")
        # Read the reconstructed payload, not just an import-success status.
        payloads = list(Path(handle.path).rglob("*.raw"))
        assert len(payloads) == 1
        assert payloads[0].read_bytes() == b"*" * 512
        assert await Snapshot.list() == []
    assert not (second / "destination").exists()
    # Admission failures remain asynchronous errors, preserving the native API contract.
    future = Snapshot.load("bad", [""])
    try:
        await future
    except Exception:
        pass
    else:
        raise AssertionError("empty archive path accepted")
    print("PYTHON_IMPORT_ADMISSION_OK")


if __name__ == "__main__":
    original = Path.cwd()
    with tempfile.TemporaryDirectory(prefix="msb-import-python-") as directory:
        try:
            asyncio.run(exercise(Path(directory).resolve()))
        finally:
            os.chdir(original)
