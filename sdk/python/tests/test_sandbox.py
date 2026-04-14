"""Tests for Sandbox lifecycle — create, exec, stop."""

import pytest

from microsandbox import Sandbox


@pytest.mark.asyncio
async def test_create_exec_stop(sandbox_name):
    """Create a sandbox, run a command, verify output, stop."""
    sb = await Sandbox.create(
        sandbox_name,
        image="alpine",
        memory=512,
        cpus=1,
        replace=True,
    )

    try:
        output = await sb.shell("echo 'hello from microsandbox'")
        assert output.success
        assert output.exit_code == 0
        assert "hello from microsandbox" in output.stdout_text
    finally:
        await sb.stop()
        await Sandbox.remove(sandbox_name)


@pytest.mark.asyncio
async def test_exec_with_args(sandbox_name):
    """Test exec with explicit args list."""
    sb = await Sandbox.create(sandbox_name, image="alpine", replace=True)

    try:
        output = await sb.exec("echo", ["-n", "test123"])
        assert output.success
        assert output.stdout_text == "test123"
    finally:
        await sb.stop()
        await Sandbox.remove(sandbox_name)


@pytest.mark.asyncio
async def test_context_manager(sandbox_name):
    """Test async with sandbox: auto-cleanup."""
    async with await Sandbox.create(sandbox_name, image="alpine", replace=True) as sb:
        output = await sb.shell("echo 'ctx'")
        assert output.success

    # Sandbox should be killed and removed after exiting the context.
    handles = await Sandbox.list()
    names = [h.name for h in handles]
    assert sandbox_name not in names


@pytest.mark.asyncio
async def test_exec_stream(sandbox_name):
    """Test streaming exec output."""
    sb = await Sandbox.create(sandbox_name, image="alpine", replace=True)

    try:
        handle = await sb.exec_stream("echo", ["stream-test"])
        collected = await handle.collect()
        assert collected.success
        assert "stream-test" in collected.stdout_text
    finally:
        await sb.stop()
        await Sandbox.remove(sandbox_name)


@pytest.mark.asyncio
async def test_sandbox_get_and_handle(sandbox_name):
    """Test Sandbox.get returns a SandboxHandle with correct metadata."""
    sb = await Sandbox.create(sandbox_name, image="alpine", replace=True)

    try:
        handle = await Sandbox.get(sandbox_name)
        assert handle.name == sandbox_name
        assert handle.status == "running"
    finally:
        await sb.stop()
        await Sandbox.remove(sandbox_name)


@pytest.mark.asyncio
async def test_sandbox_list():
    """Test Sandbox.list returns a list of handles."""
    handles = await Sandbox.list()
    assert isinstance(handles, list)
