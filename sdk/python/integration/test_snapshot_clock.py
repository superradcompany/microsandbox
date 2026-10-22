"""Explicit policy and omission on real disk/full archives from the host architecture."""

import json
import os
from contextlib import suppress
from uuid import uuid4

import pytest

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
            handle = await Sandbox.get(name)
            expected = policy or os.environ.get("MSB_CLOCK_EXPECTED", "sync")
            actual = json.loads(handle.config_json)["runtime"].get("guest_clock", "sync")
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
