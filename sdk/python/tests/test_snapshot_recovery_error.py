"""Partial capture failures preserve a usable artifact locator, not a success result."""

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
