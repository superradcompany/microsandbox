"""Real-runtime checks for the accepted SDK revamp contracts."""

from __future__ import annotations

import asyncio
from contextlib import suppress

import pytest

from microsandbox import (
    ExecEventType,
    ExecTimeoutError,
    LocalContext,
    MicrosandboxError,
    Sandbox,
    SandboxStatus,
    Volume,
)


@pytest.mark.asyncio
@pytest.mark.parametrize("code", [0, 7])
@pytest.mark.parametrize("observation", ["wait", "collect", "recv"])
async def test_completion_remains_observable(sandbox_factory, observation, code):
    sandbox = await sandbox_factory("py-sdk-completion")
    execution = await sandbox.shell_stream(
        f"echo ran >> /tmp/completion-runs; printf output; exit {code}"
    )
    if observation == "collect":
        output = await execution.collect()
        assert output.stdout_bytes == b"output"
        assert output.exit_code == code
    elif observation == "recv":
        events = [event async for event in execution]
        assert [event.code for event in events if event.event_type is ExecEventType.EXITED] == [
            code
        ]
    else:
        assert await execution.wait() == (code, code == 0)

    # Waiting observes the same execution; neither output retention nor rerunning is required.
    for _ in range(2):
        assert await execution.wait() == (code, code == 0)
    assert await execution.recv() is None
    assert (await sandbox.shell("wc -l < /tmp/completion-runs")).stdout_text.strip() == "1"


@pytest.mark.asyncio
async def test_live_config_observes_another_client(sandbox_factory):
    sandbox = await sandbox_factory("py-sdk-live-config", labels={"revision": "first"})
    observer = await Sandbox.get(sandbox.name)
    captured = await observer.config()
    await sandbox.modify(labels={"revision": "second"})
    assert captured["spec"]["labels"]["revision"] == "first"
    assert (await observer.config())["spec"]["labels"]["revision"] == "second"


@pytest.mark.asyncio
async def test_implicit_start_and_borrowed_scope_ownership(sandbox_factory):
    original = await sandbox_factory("py-sdk-implicit")
    name, identity = original.name, original.id
    await original.stop()
    receiver = await Sandbox.get(name)
    assert receiver.id == identity
    assert await receiver.status() is SandboxStatus.STOPPED
    await receiver.config()
    assert await receiver.status() is SandboxStatus.STOPPED
    assert await receiver.owns_lifecycle is False
    async with receiver:
        assert (await receiver.shell("printf prepared")).stdout_text == "prepared"
        assert await receiver.owns_lifecycle is True
        assert await receiver.ensure_running() is None
        async with await Sandbox.get_running(name) as borrower:
            assert await borrower.owns_lifecycle is False
        assert await receiver.status() is SandboxStatus.RUNNING
    observer = await Sandbox.get(name)
    assert observer.id == identity
    assert await asyncio.wait_for(observer.wait_for_status(SandboxStatus.STOPPED), 20) is None


@pytest.mark.asyncio
async def test_stale_receiver_does_not_destroy_replacement(sandbox_factory):
    first = await sandbox_factory("py-sdk-identity")
    stale = await Sandbox.get(first.name)
    await first.stop()
    replacement = await Sandbox.create(first.name, image="alpine", memory=512, replace=True)
    try:
        assert replacement.id != stale.id
        with pytest.raises(MicrosandboxError):
            await stale.destroy()
        assert (await replacement.shell("printf replacement")).stdout_text == "replacement"
    finally:
        await replacement.stop()


@pytest.mark.asyncio
async def test_owned_and_borrowed_scope_cleanup(sandbox_factory):
    original = await sandbox_factory("py-sdk-scope")
    await original.stop()
    receiver = await Sandbox.get(original.name)
    async with receiver:
        # Check the lifetime independently from the exact completion return value.
        await receiver.ensure_running()
        assert await receiver.owns_lifecycle is True
        async with await Sandbox.get_running(receiver.name) as borrower:
            assert await borrower.owns_lifecycle is False
        assert await receiver.status() is SandboxStatus.RUNNING
    observer = await Sandbox.get(original.name)
    assert observer.id == original.id
    assert await asyncio.wait_for(observer.wait_for_status(SandboxStatus.STOPPED), 20) is None


@pytest.mark.asyncio
async def test_cancelled_wait_does_not_finish_execution(sandbox_factory):
    sandbox = await sandbox_factory("py-sdk-cancel-wait")
    execution = await sandbox.shell_stream("sleep 0.3; exit 7")
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(execution.wait(), 0.03)
    assert await execution.wait() == (7, False)
    assert await execution.wait() == (7, False)


@pytest.mark.asyncio
async def test_terminal_execution_failure_is_repeatable(sandbox_factory):
    sandbox = await sandbox_factory("py-sdk-terminal-failure")
    execution = await sandbox.shell_stream("sleep 30", timeout=0.05)
    failures = []
    for _ in range(2):
        with pytest.raises(ExecTimeoutError) as failure:
            await execution.wait()
        failures.append(str(failure.value))
    assert failures[0] == failures[1]


@pytest.mark.asyncio
async def test_inspection_failure_never_returns_saved_state(sandbox_factory):
    sandbox = await sandbox_factory("py-sdk-inspection-failure")
    observer = await Sandbox.get(sandbox.name)
    await observer.info()
    await observer.config()
    await sandbox.destroy()
    for read in (observer.info, observer.config, observer.status, observer.last_failure_message):
        with pytest.raises(MicrosandboxError):
            await read()


@pytest.mark.asyncio
async def test_local_volume_contexts_retain_distinct_destinations(tmp_path):
    first_context = LocalContext(home=(tmp_path / "first").resolve())
    second_context = LocalContext(home=(tmp_path / "second").resolve())
    first = await Volume.ctx(first_context).create("same-name")
    second = await second_context.volumes.create("same-name")
    del first_context, second_context
    try:
        # IDs are destination-scoped; two independent catalogs may both start at local:1.
        assert first.path != second.path
        await asyncio.gather(
            first.fs.write("marker", b"first"), second.fs.write("marker", b"second")
        )
        assert await first.fs.read("marker") == b"first"
        assert await second.fs.read("marker") == b"second"
        fetched = await first.context.volumes.get("same-name")
        assert fetched.id == first.id
        await first.destroy()
        with pytest.raises(MicrosandboxError):
            await fetched.info()
        assert await second.fs.read("marker") == b"second"
    finally:
        for volume in (first, second):
            with suppress(MicrosandboxError):
                await volume.destroy()


@pytest.mark.asyncio
async def test_paginated_results_are_usable_unified_resources(sandbox_factory, sandbox_name):
    owner = sandbox_name("py-sdk-page-owner")
    sandboxes = [
        await sandbox_factory("py-sdk-page", labels={"parity_owner": owner}) for _ in range(3)
    ]
    seen = set()
    cursor = None
    # A bounded traversal fails if the provider repeats a cursor or never terminates.
    for _ in range(4):
        page = await Sandbox.list_with(limit=1, cursor=cursor, labels={"parity_owner": owner})
        for item in page.sandboxes:
            assert isinstance(item, Sandbox)
            assert item.id not in seen
            seen.add(item.id)
            assert (await item.shell("printf listed")).stdout_text == "listed"
        if page.next_cursor is None:
            break
        assert page.next_cursor != cursor
        cursor = page.next_cursor
    else:
        pytest.fail("pagination did not terminate")
    assert seen == {sandbox.id for sandbox in sandboxes}
