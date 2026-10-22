"""Snapshot integration tests."""

from __future__ import annotations

from contextlib import suppress
from pathlib import Path

import pytest

from integration.helpers import IMAGE, remove_sandbox, remove_snapshot
from microsandbox import (
    Checkpoint,
    Image,
    Sandbox,
    Snapshot,
    SnapshotFormat,
    SnapshotScope,
    SnapshotStateKind,
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "source_kind",
    ["member", "group", "id", "directory", "pathlike", "archive", "snapshot", "handle"],
)
async def test_snapshot_create_open_list_and_boot(sandbox_name, tmp_path, source_kind):
    base_name = sandbox_name("py-sdk-snap-base")
    fork_name = sandbox_name("py-sdk-snap-fork")
    snapshot_name = sandbox_name("py-sdk-snap")

    await remove_sandbox(fork_name)
    await remove_sandbox(base_name)
    snapshot_selector = f"{snapshot_name}:ready"
    await remove_snapshot(snapshot_selector)

    base = await Sandbox.create(
        base_name, image=Image.oci(IMAGE, root_disk=256), cpus=1, memory=512, replace=True
    )
    fork = None
    copied_group = None
    group = None
    try:
        assert (await base.shell("printf restored-user-data > /root/snapshot-marker; sync")).success
        await base.stop()

        base_handle = await Sandbox.get(base_name)
        created = await base_handle.snapshot(
            snapshot_name, initial_checkpoint="ready", record_integrity=True
        )
        group = created.snapshot
        snapshot = created.checkpoint
        assert snapshot.digest
        assert snapshot.reference
        assert snapshot.reference_kind == "path"
        assert snapshot.size_bytes > 0
        assert snapshot.source_sandbox == base_name
        assert snapshot.state_kind is SnapshotStateKind.FILE
        assert snapshot.format is SnapshotFormat.RAW
        assert snapshot.scope is SnapshotScope.DISK

        verify_result = await snapshot.verify()
        assert isinstance(verify_result, dict)

        handle = await Checkpoint.get(snapshot_selector)
        assert handle.digest == snapshot.digest
        assert handle.state_kind is SnapshotStateKind.FILE
        assert handle.format is SnapshotFormat.RAW
        assert handle.scope is SnapshotScope.DISK
        assert handle.group == snapshot_name
        assert snapshot.head_update["reason"] == "initialized"
        head = await group.head()
        assert head is not None and head.id == snapshot.id
        selected = await group.set_head("ready")
        assert selected["changed"] is False
        assert selected["head"] == snapshot.id
        opened = await handle.open()
        assert opened.digest == snapshot.digest
        assert opened.state_kind is SnapshotStateKind.FILE

        snapshots = await Checkpoint.list()
        assert any(item.digest == snapshot.digest for item in snapshots)

        # All public selector forms must reach the same Rust resolver. In particular, a
        # group:member selector is not a literal directory underneath MSB_HOME/snapshots.
        sources = {
            "member": snapshot_selector,
            "group": snapshot_name,
            "id": snapshot.id,
            "directory": snapshot.path,
            "pathlike": Path(snapshot.path),
            "snapshot": snapshot,
            "handle": handle,
        }
        if source_kind == "archive":
            archive = tmp_path / "saved.msb"
            await snapshot.save(str(archive))
            source = archive
        else:
            source = sources[source_kind]

        fork = await Sandbox.restore(source, name=fork_name)
        out = await fork.shell("cat /etc/alpine-release")
        assert out.success is True
        assert out.stdout_text.strip()
        assert (await fork.shell("cat /root/snapshot-marker")).stdout_text == "restored-user-data"

        # Restore by ID while it still identifies one local artifact. Importing the copy
        # below intentionally makes that selector ambiguous.
        copied_archive = tmp_path / "copied.tar.zst"
        await (
            snapshot.copy_to(copied_archive)
            .labels({"environment": "test"})
            .record_integrity(True)
            .save()
        )
        imported = await Snapshot.load(
            sandbox_name("copied-history"), [copied_archive],
            dest=tmp_path / "copied-artifact", set_head=True,
        )
        copied_group = imported.snapshot
        assert len(imported.checkpoints) == len(imported.added) == 1
        copied = await imported.checkpoints[0].open()
        assert copied.labels == {"environment": "test"}
        assert (await copied.verify())["upper"]["kind"] == "verified"
    finally:
        if copied_group is not None:
            await copied_group.remove()
        if fork is not None:
            with suppress(Exception):
                await fork.stop()
        await remove_sandbox(fork_name)
        await remove_sandbox(base_name)
        if group is not None:
            await group.remove()
