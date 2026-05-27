"""Pytest fixtures for Python SDK integration tests."""

from __future__ import annotations

from contextlib import suppress
from typing import Any

import pytest

from integration.helpers import IMAGE, remove_sandbox, remove_volume, unique_name
from microsandbox import Sandbox, Volume


@pytest.fixture
def sandbox_name() -> Any:
    return unique_name


@pytest.fixture
async def sandbox_factory() -> Any:
    sandboxes: list[tuple[str, Any]] = []

    async def create(prefix: str = "py-sdk", **kwargs: Any) -> Any:
        name = unique_name(prefix)
        await remove_sandbox(name)
        config: dict[str, Any] = {
            "image": IMAGE,
            "cpus": 1,
            "memory": 512,
            "replace": True,
        }
        config.update(kwargs)
        try:
            sandbox = await Sandbox.create(name, **config)
        except Exception:
            await remove_sandbox(name)
            raise
        sandboxes.append((name, sandbox))
        return sandbox

    yield create

    for name, sandbox in reversed(sandboxes):
        with suppress(Exception):
            await sandbox.stop_and_wait()
        await remove_sandbox(name)


@pytest.fixture
async def volume_factory() -> Any:
    volumes: list[str] = []

    async def create(prefix: str = "py-sdk-vol", **kwargs: Any) -> Any:
        name = unique_name(prefix)
        await remove_volume(name)
        volume = await Volume.create(name, **kwargs)
        volumes.append(name)
        return volume

    yield create

    for name in reversed(volumes):
        await remove_volume(name)
