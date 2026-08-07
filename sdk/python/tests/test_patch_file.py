"""Unit tests for raw-byte root filesystem patches."""

from __future__ import annotations

import pytest

from microsandbox import Patch, PatchConfig, PatchKind


def test_file_patch_serializes_raw_bytes() -> None:
    patch = Patch.file("/opt/blob.bin", b"\x00\xff", mode=0o600, replace=True)

    assert patch._to_dict() == {
        "kind": "file",
        "path": "/opt/blob.bin",
        "content": b"\x00\xff",
        "mode": 0o600,
        "replace": True,
    }


def test_file_patch_rejects_text_content() -> None:
    patch = PatchConfig(
        kind=PatchKind.FILE,
        path="/opt/blob.bin",
        content="not raw bytes",
    )

    with pytest.raises(TypeError, match="requires content to be bytes"):
        patch._to_dict()


def test_text_patch_rejects_raw_bytes() -> None:
    patch = PatchConfig(
        kind=PatchKind.TEXT,
        path="/etc/app.conf",
        content=b"not text",
    )

    with pytest.raises(TypeError, match="requires content to be str"):
        patch._to_dict()
