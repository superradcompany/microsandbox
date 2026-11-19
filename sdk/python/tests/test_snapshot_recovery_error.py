"""Partial capture failures preserve a usable artifact locator, not a success result."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from microsandbox import MicrosandboxError, SnapshotSourceRecoveryError


@pytest.mark.parametrize("kind", ["installed", "archive"])
def test_saved_artifact_is_structured(kind: str) -> None:
    error = SnapshotSourceRecoveryError(
        "saved; source recovery failed",
        source_sandbox="source",
        checkpoint_id="checkpoint-1",
        checkpoint_root="root-1",
        checkpoint_path="/runtime/checkpoint-1",
        artifact={"kind": kind, "path": "/saved", "snapshot_id": "snap_1", "digest": "digest-1"},
        detail="thaw acknowledgement timed out",
        publication_error=None,
    )
    assert isinstance(error, MicrosandboxError)
    assert error.code == "snapshot-source-recovery"
    assert error.artifact is not None
    assert error.artifact.kind == kind
    assert error.artifact.path == "/saved"
    assert error.artifact.snapshot_id == "snap_1"
    assert error.artifact.head_update is None
    assert error.source_sandbox == "source"
    assert error.publication_error is None


def test_failed_publication_never_advertises_an_artifact() -> None:
    error = SnapshotSourceRecoveryError(
        "checkpoint retained; publication and source recovery failed",
        source_sandbox="source",
        checkpoint_id="checkpoint-1",
        checkpoint_root="root-1",
        checkpoint_path="/runtime/checkpoint-1",
        artifact=None,
        detail="resume failed",
        publication_error="disk full",
    )
    assert error.artifact is None
    assert error.checkpoint_path == "/runtime/checkpoint-1"
    assert error.detail == "resume failed"
    assert error.publication_error == "disk full"


@pytest.mark.parametrize("outcome", ["not_committed", "committed", "unknown"])
def test_import_preserves_publication_outcome(outcome: str) -> None:
    from microsandbox import SnapshotImportError

    archives = ["/base.msb", "/child.msb"]
    error = SnapshotImportError(
        "import failed",
        operation_id="attempt-1",
        archives=archives,
        group_path="/snapshots/history",
        outcome=outcome,
        detail="index write failed",
    )
    archives.clear()
    assert isinstance(error, MicrosandboxError)
    assert error.code == "snapshot-import"
    assert error.operation_id == "attempt-1"
    assert error.archives == ["/base.msb", "/child.msb"]
    assert error.outcome == outcome
    assert error.group_path == "/snapshots/history"
    assert error.detail == "index write failed"


@pytest.mark.parametrize("api", ["group", "legacy"])
def test_native_import_failure_retains_batch_context(tmp_path: Path, api: str) -> None:
    # A subprocess selects an isolated local home before native backend initialization.
    # No VM is needed: malformed archive bytes fail before group publication.
    archive = tmp_path / "invalid.msb"
    archive.write_bytes(b"not an archive")
    result = subprocess.run(
        [sys.executable, "-c", """
import asyncio
import sys
from microsandbox import Snapshot, Checkpoint, SnapshotImportError

async def main():
    try:
        if sys.argv[2] == "group":
            await Snapshot.load("history", [sys.argv[1]])
        else:
            await Checkpoint.load_many([sys.argv[1]], group="history")
    except SnapshotImportError as error:
        assert error.outcome == "not_committed", error.outcome
        assert error.archives == [sys.argv[1]], error.archives
        assert len(error.operation_id) == 32, error.operation_id
        assert error.group_path is None, error.group_path
        assert error.detail
    else:
        raise AssertionError("malformed archive was accepted")

asyncio.run(main())
""", str(archive), api],
        env={**os.environ, "MSB_HOME": str(tmp_path / "home")},
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert not (tmp_path / "home" / "snapshots" / "history" / "group.json").exists()


def test_published_artifact_retains_operation_head_outcome() -> None:
    from microsandbox import PublishedSnapshotArtifact

    update = {
        "group": "history", "previous": None, "head": "snap_1",
        "reason": "initialized", "changed": True,
    }
    artifact = PublishedSnapshotArtifact(
        kind="installed", path="/saved", snapshot_id="snap_1", digest="digest-1", head_update=update
    )
    assert artifact.head_update == update
