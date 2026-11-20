"""Explicit policy and omission on real disk/full archives from the host architecture."""

import os
from contextlib import suppress
from uuid import uuid4

import pytest

from integration.helpers import stop_and_remove_sandbox
from microsandbox import Sandbox, Snapshot


@pytest.mark.asyncio
async def test_snapshot_guest_clock_inheritance_and_override():
    archive = os.environ.get("MSB_CLOCK_ARCHIVE")
    if not archive:
        pytest.skip("requires a disk/full archive from the current host architecture")
    imported = await Snapshot.load("python-clock-" + uuid4().hex[:8], [archive])
    group = imported.snapshot
    checkpoint = await group.head()
    assert checkpoint is not None
    names = []
    try:
        for source, policy, progress in [
            (group, None, False),
            (checkpoint, "sync", False),
            (group, "off", True),
            (checkpoint, None, True),
        ]:
            name = "python-clock-" + uuid4().hex[:8]
            names.append(name)
            options = {} if policy is None else {"guest_clock": policy}
            if progress:
                session = await source.spawn_sandbox_with_progress(name=name, **options)
                child = await session.result()
            else:
                child = await source.spawn_sandbox(name=name, **options)
            expected = policy or os.environ.get("MSB_CLOCK_EXPECTED", "sync")
            actual = (await child.config())["spec"]["runtime"].get("guest_clock", "sync")
            assert actual == expected
            assert (await child.shell("cat /root/clock-marker")).stdout_text == "clock-marker"
            await child.stop()
    finally:
        for name in names:
            with suppress(Exception):
                await (await Sandbox.get(name)).stop()
            with suppress(Exception):
                await Sandbox.remove(name)
        await group.remove()


@pytest.mark.asyncio
async def test_new_disk_checkpoint_keeps_observed_clock(sandbox_factory, sandbox_name):
    seed = await sandbox_factory("clock-seed")
    initial = await seed.snapshot(sandbox_name("clock-seed-group"))
    captured = None
    try:
        name = sandbox_name("clock-source")
        source = await initial.checkpoint.spawn_sandbox(name=name, guest_clock="off")
        try:
            captured = await source.snapshot(sandbox_name("clock-group"))
        finally:
            await source.stop()
            await Sandbox.remove(name)

        # Restore must derive the policy from the checkpoint after source removal.
        for override in (None, "sync"):
            name = sandbox_name("clock-child")
            options = {} if override is None else {"guest_clock": override}
            child = await captured.checkpoint.spawn_sandbox(name=name, **options)
            try:
                runtime = (await child.config())["spec"]["runtime"]
                assert runtime.get("guest_clock", "sync") == (override or "off")
                assert (await child.shell("true")).success
            finally:
                await stop_and_remove_sandbox(name, child)
    finally:
        if captured is not None:
            await captured.snapshot.remove()
        await initial.snapshot.remove()
