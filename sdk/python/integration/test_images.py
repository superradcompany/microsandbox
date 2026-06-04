from __future__ import annotations

import pytest

from integration.helpers import IMAGE
from microsandbox import Image, ImageHandle, ImageInUseError, ImageNotFoundError


async def test_image_list_returns_cached_handles() -> None:
    images = await Image.list()

    assert isinstance(images, list)
    for image in images:
        assert isinstance(image, ImageHandle)
        assert image.reference
        assert image.layer_count >= 0


async def test_image_get_missing_raises_typed_error() -> None:
    with pytest.raises(ImageNotFoundError):
        await Image.get("example.invalid/missing:python-sdk-image-test")


async def test_image_management_round_trips_pulled_sandbox_image(sandbox_factory) -> None:
    await sandbox_factory("py-sdk-image-cache", pull_policy="if_missing")

    handle = await Image.get(IMAGE)
    assert isinstance(handle, ImageHandle)
    assert handle.reference == IMAGE
    assert handle.layer_count > 0

    images = await Image.list()
    assert any(image.reference == IMAGE for image in images)

    detail = await Image.inspect(IMAGE)
    assert detail.handle.reference == IMAGE
    assert detail.handle.layer_count == handle.layer_count
    assert len(detail.layers) == handle.layer_count
    assert all(layer.diff_id for layer in detail.layers)
    assert all(layer.blob_digest for layer in detail.layers)

    handle_detail = await handle.inspect()
    assert handle_detail.handle.reference == IMAGE
    assert len(handle_detail.layers) == len(detail.layers)

    with pytest.raises(ImageInUseError):
        await handle.remove()
