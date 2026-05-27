"""Shared helpers for Python SDK integration tests."""

from __future__ import annotations

import os
import socket
import uuid
from contextlib import suppress
from pathlib import Path
from typing import Any

from microsandbox import Sandbox, Snapshot, Volume

IMAGE = os.environ.get("MICROSANDBOX_PYTHON_INTEGRATION_IMAGE", "mirror.gcr.io/library/alpine")


def unique_name(prefix: str) -> str:
    run_id = os.environ.get("GITHUB_RUN_ID") or str(os.getpid())
    return f"{prefix}-{run_id}-{uuid.uuid4().hex[:8]}"


def free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


async def remove_sandbox(name: str) -> None:
    with suppress(Exception):
        await Sandbox.remove(name)


async def stop_and_remove_sandbox(name: str, sandbox: Any | None = None) -> None:
    if sandbox is not None:
        with suppress(Exception):
            await sandbox.stop_and_wait()
    await remove_sandbox(name)


async def remove_volume(name: str) -> None:
    with suppress(Exception):
        await Volume.remove(name)


async def remove_snapshot(path_or_name: str | Path) -> None:
    with suppress(Exception):
        await Snapshot.remove(str(path_or_name), force=True)
