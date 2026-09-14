"""Compatibility for the legacy local snapshot path accessor."""

import json
from pathlib import Path

import pytest

from microsandbox import Snapshot, SnapshotHandle


@pytest.mark.asyncio
async def test_local_snapshot_path(tmp_path: Path) -> None:
    manifest = {
        "schema": 1,
        "artifact": "snapshot",
        "scope": "disk",
        "created_at": "2026-05-01T12:00:00Z",
        "parent": None,
        "image": {
            "ref": "docker.io/library/alpine:3.20",
            "manifest_digest": "sha256:" + "a" * 64,
        },
        "source_sandbox": None,
        "state": {
            "kind": "file",
            "format": "raw",
            "fstype": "ext4",
            "upper": {"file": "upper.ext4", "size_bytes": 5, "integrity": None},
        },
        "labels": {},
        "extensions": {},
        "requires": [],
    }
    (tmp_path / "snapshot.json").write_text(json.dumps(manifest))
    (tmp_path / "upper.ext4").write_bytes(b"hello")
    snapshot = await Snapshot.open(str(tmp_path))
    assert snapshot.path == str(tmp_path.resolve())
    assert snapshot.reference == snapshot.path
    assert snapshot.reference_kind == "path"
    assert hasattr(SnapshotHandle, "path")
