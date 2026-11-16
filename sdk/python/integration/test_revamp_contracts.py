"""Real-runtime checks for the accepted SDK revamp contracts."""

from __future__ import annotations

import asyncio

import pytest

from microsandbox import ExecEventType, MicrosandboxError, Sandbox, SandboxStatus


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
    assert captured["labels"]["revision"] == "first"
    assert (await observer.config())["labels"]["revision"] == "second"


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
