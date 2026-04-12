"""Tests for command execution."""

import pytest

from microsandbox import Sandbox


@pytest.mark.asyncio
async def test_exec_exit_code(sandbox_name):
    """Test non-zero exit code."""
    async with await Sandbox.create(sandbox_name, image="alpine", replace=True) as sb:
        output = await sb.shell("exit 42")
        assert not output.success
        assert output.exit_code == 42


@pytest.mark.asyncio
async def test_exec_stderr(sandbox_name):
    """Test stderr capture."""
    async with await Sandbox.create(sandbox_name, image="alpine", replace=True) as sb:
        output = await sb.shell("echo 'err' >&2")
        assert "err" in output.stderr_text


@pytest.mark.asyncio
async def test_exec_stream_events(sandbox_name):
    """Test iterating over exec stream events."""
    async with await Sandbox.create(sandbox_name, image="alpine", replace=True) as sb:
        handle = await sb.exec_stream("echo", ["event-test"])
        events = []
        async for event in handle:
            events.append(event)

        event_types = [e.event_type for e in events]
        assert "stdout" in event_types
        assert "exited" in event_types


@pytest.mark.asyncio
async def test_shell_multiline(sandbox_name):
    """Test multi-line shell script."""
    async with await Sandbox.create(sandbox_name, image="alpine", replace=True) as sb:
        output = await sb.shell("echo line1\necho line2")
        assert "line1" in output.stdout_text
        assert "line2" in output.stdout_text


@pytest.mark.asyncio
async def test_exec_with_options_dict(sandbox_name):
    """Test exec with ExecOptions-style dict."""
    async with await Sandbox.create(sandbox_name, image="alpine", replace=True) as sb:
        output = await sb.exec("sh", {"args": ["-c", "echo $FOO"], "env": {"FOO": "bar123"}})
        assert "bar123" in output.stdout_text
