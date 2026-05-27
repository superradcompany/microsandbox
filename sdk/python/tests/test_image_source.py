"""Unit tests for explicit image source dataclasses."""

from __future__ import annotations

from microsandbox import Image


def test_oci_accepts_upper_size_mib() -> None:
    image = Image.oci("python:3.12", upper_size_mib=8192)

    assert image._type == "oci"
    assert image._reference == "python:3.12"
    assert image._upper_size_mib == 8192
    assert image._to_image_str() == "python:3.12"
