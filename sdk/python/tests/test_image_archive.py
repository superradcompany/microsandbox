"""Unit tests for image archive save argument validation."""

from __future__ import annotations

import pathlib

import pytest

from microsandbox import Image


async def test_save_rejects_unknown_format(tmp_path: pathlib.Path) -> None:
    with pytest.raises(ValueError, match="invalid archive format"):
        await Image.save(
            "python:3.12",
            output_path=str(tmp_path / "image.tar"),
            format="zip",
        )
