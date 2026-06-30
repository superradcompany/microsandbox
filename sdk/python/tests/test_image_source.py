"""Unit tests for explicit image source dataclasses."""

from __future__ import annotations

from microsandbox import Image, ImageSource


def test_oci_creates_image_source() -> None:
    image = Image.oci("python:3.12")

    assert isinstance(image, ImageSource)
    assert image._type == "oci"
    assert image._reference == "python:3.12"
    assert image._to_image_str() == "python:3.12"


def test_image_namespace_includes_cache_management() -> None:
    assert hasattr(Image, "get")
    assert hasattr(Image, "list")
    assert hasattr(Image, "inspect")
    assert hasattr(Image, "remove")
    assert hasattr(Image, "prune")
