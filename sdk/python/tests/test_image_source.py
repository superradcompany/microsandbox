"""Unit tests for explicit image source dataclasses."""

from __future__ import annotations

import pytest

from microsandbox import Image, ImageSource, RootDisk, RootDiskConfig


def test_oci_accepts_root_disk_int() -> None:
    image = Image.oci("python:3.12", root_disk=8192)

    assert isinstance(image, ImageSource)
    assert image._type == "oci"
    assert image._reference == "python:3.12"
    assert image._root_disk == 8192
    assert image._to_image_str() == "python:3.12"


def test_oci_accepts_managed_root_disk() -> None:
    image = Image.oci("python:3.12", root_disk=RootDisk.managed(8192))

    assert isinstance(image._root_disk, RootDiskConfig)
    assert image._root_disk._to_dict() == {"kind": "managed", "size_mib": 8192}


def test_oci_accepts_tmpfs_root_disk() -> None:
    image = Image.oci("python:3.12", root_disk=RootDisk.tmpfs(512))

    assert isinstance(image._root_disk, RootDiskConfig)
    assert image._root_disk._to_dict() == {"kind": "tmpfs", "size_mib": 512}


def test_oci_accepts_disk_image_root_disk() -> None:
    image = Image.oci(
        "python:3.12",
        root_disk=RootDisk.disk("./scratch.img", format="raw", fstype="ext4"),
    )

    assert isinstance(image._root_disk, RootDiskConfig)
    assert image._root_disk._to_dict() == {
        "kind": "disk-image",
        "path": "./scratch.img",
        "format": "raw",
        "fstype": "ext4",
    }


def test_oci_accepts_deprecated_upper_size_mib_alias() -> None:
    image = Image.oci("python:3.12", upper_size_mib=8192)

    assert isinstance(image, ImageSource)
    assert image._upper_size_mib == 8192
    # The alias normalizes to a managed root disk.
    root_disk = image._root_disk
    if isinstance(root_disk, RootDiskConfig):
        root_disk = root_disk._to_dict()
    assert root_disk == {"kind": "managed", "size_mib": 8192}


def test_oci_rejects_root_disk_and_upper_size_mib_together() -> None:
    with pytest.raises(ValueError):
        Image.oci("python:3.12", root_disk=8192, upper_size_mib=8192)


def test_image_namespace_includes_cache_management() -> None:
    assert hasattr(Image, "get")
    assert hasattr(Image, "list")
    assert hasattr(Image, "inspect")
    assert hasattr(Image, "remove")
    assert hasattr(Image, "prune")
