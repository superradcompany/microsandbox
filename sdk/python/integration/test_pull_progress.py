"""Pull-progress integration tests."""

from __future__ import annotations

from contextlib import suppress

import pytest

from integration.helpers import IMAGE, remove_sandbox
from microsandbox import MicrosandboxError, PullEventType, PullPolicy, Sandbox


@pytest.mark.asyncio
async def test_create_with_progress_emits_events_and_returns_sandbox(sandbox_name):
    name = sandbox_name("py-sdk-progress")
    await remove_sandbox(name)

    session = Sandbox.create_with_progress(
        name,
        image=IMAGE,
        cpus=1,
        memory=512,
        replace=True,
        pull_policy=PullPolicy.ALWAYS,
    )

    sandbox = None
    try:
        events = []
        async with session:
            async for event in session.progress:
                events.append(event)
            sandbox = await session.result()

        event_types = [event.event_type for event in events]
        assert all(isinstance(event_type, PullEventType) for event_type in event_types)
        assert event_types[0] is PullEventType.RESOLVING
        assert PullEventType.RESOLVED in event_types
        assert event_types[-1] is PullEventType.COMPLETE

        resolved = next(event for event in events if event.event_type is PullEventType.RESOLVED)
        assert resolved.reference
        assert resolved.manifest_digest
        assert resolved.layer_count > 0

        complete = events[-1]
        assert complete.reference == resolved.reference
        assert complete.layer_count == resolved.layer_count

        assert await sandbox.name == name
    finally:
        if sandbox is not None:
            with suppress(Exception):
                await sandbox.stop()
        await remove_sandbox(name)


@pytest.mark.asyncio
async def test_create_with_progress_result_rejects_on_second_call(sandbox_name):
    name = sandbox_name("py-sdk-progress-once")
    await remove_sandbox(name)

    session = Sandbox.create_with_progress(
        name,
        image=IMAGE,
        cpus=1,
        memory=512,
        replace=True,
    )

    sandbox = None
    try:
        async with session:
            async for _event in session.progress:
                pass
            sandbox = await session.result()
            with pytest.raises(RuntimeError, match="already consumed"):
                await session.result()
    finally:
        if sandbox is not None:
            with suppress(Exception):
                await sandbox.stop()
        await remove_sandbox(name)


@pytest.mark.asyncio
async def test_create_with_progress_detached_returns_detached_sandbox(sandbox_name):
    name = sandbox_name("py-sdk-progress-detached")
    await remove_sandbox(name)

    session = Sandbox.create_with_progress(
        name,
        image=IMAGE,
        cpus=1,
        memory=512,
        replace=True,
        detached=True,
    )

    sandbox = None
    handle = None
    connected = None
    try:
        event_types = []
        async with session:
            async for event in session.progress:
                event_types.append(event.event_type)
            sandbox = await session.result()

        assert all(isinstance(event_type, PullEventType) for event_type in event_types)
        assert event_types[0] is PullEventType.RESOLVING
        assert PullEventType.RESOLVED in event_types
        assert event_types[-1] is PullEventType.COMPLETE
        assert await sandbox.name == name
        assert await sandbox.owns_lifecycle is False

        sandbox = None

        handle = await Sandbox.get(name)
        connected = await handle.connect()
        assert await connected.owns_lifecycle is False
        out = await connected.shell("printf 'detached-progress\\n'")
        assert out.success is True
        assert out.stdout_text == "detached-progress\n"
    finally:
        if connected is not None:
            with suppress(Exception):
                await connected.detach()
        if sandbox is not None:
            with suppress(Exception):
                await sandbox.stop()
        if handle is None:
            with suppress(Exception):
                handle = await Sandbox.get(name)
        if handle is not None:
            with suppress(Exception):
                await handle.stop(timeout=10.0)
        await remove_sandbox(name)


@pytest.mark.asyncio
async def test_create_with_progress_failure_surfaces_from_result(sandbox_name):
    name = sandbox_name("py-sdk-progress-error")
    await remove_sandbox(name)

    session = Sandbox.create_with_progress(
        name,
        image="sdk-nonexistent-image-xyz789:never",
        cpus=1,
        memory=512,
        replace=True,
        pull_policy=PullPolicy.NEVER,
    )

    async with session:
        async for _event in session.progress:
            pass
        with pytest.raises(MicrosandboxError):
            await session.result()
