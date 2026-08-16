"""Snapshot integration tests."""

from __future__ import annotations

from contextlib import suppress

import pytest

from integration.helpers import IMAGE, remove_sandbox, remove_snapshot
from microsandbox import (
    Sandbox,
    Snapshot,
    SnapshotFormat,
    SnapshotScope,
    SnapshotStateKind,
)


@pytest.mark.asyncio
async def test_snapshot_create_open_list_and_boot(sandbox_name):
    base_name = sandbox_name("py-sdk-snap-base")
    fork_name = sandbox_name("py-sdk-snap-fork")
    snapshot_name = sandbox_name("py-sdk-snap")

    await remove_sandbox(fork_name)
    await remove_sandbox(base_name)
    await remove_snapshot(snapshot_name)

    base = await Sandbox.create(base_name, image=IMAGE, cpus=1, memory=512, replace=True)
    fork = None
    try:
        await base.stop()

        base_handle = await Sandbox.get(base_name)
        snapshot = await base_handle.snapshot(snapshot_name)
        assert snapshot.digest
        assert snapshot.path
        assert snapshot.size_bytes > 0
        assert snapshot.source_sandbox == base_name
        assert snapshot.state_kind is SnapshotStateKind.FILE
        assert snapshot.format is SnapshotFormat.RAW
        assert snapshot.scope is SnapshotScope.DISK

        verify_result = await snapshot.verify()
        assert isinstance(verify_result, dict)

        handle = await Snapshot.get(snapshot_name)
        assert handle.digest == snapshot.digest
        assert handle.state_kind is SnapshotStateKind.FILE
        assert handle.format is SnapshotFormat.RAW
        assert handle.scope is SnapshotScope.DISK
        opened = await handle.open()
        assert opened.digest == snapshot.digest
        assert opened.state_kind is SnapshotStateKind.FILE

        snapshots = await Snapshot.list()
        assert any(item.digest == snapshot.digest for item in snapshots)

        fork = await Sandbox.create(
            fork_name,
            from_snapshot=snapshot_name,
            cpus=1,
            memory=512,
            replace=True,
        )
        out = await fork.shell("cat /etc/alpine-release")
        assert out.success is True
        assert out.stdout_text.strip()
    finally:
        if fork is not None:
            with suppress(Exception):
                await fork.stop()
        await remove_sandbox(fork_name)
        await remove_sandbox(base_name)
        await remove_snapshot(snapshot_name)
