"""Metrics and logs integration tests."""

from __future__ import annotations

import asyncio

import pytest

from microsandbox import MicrosandboxError, Sandbox, all_sandbox_metrics


async def wait_for_metrics(sandbox):
    last_error = None

    # The runtime publishes the live metrics slot asynchronously after boot
    # readiness, so the first metrics snapshot may race slot creation.
    for _ in range(20):
        try:
            return await sandbox.metrics()
        except MicrosandboxError as error:
            if "no live metrics slot" not in str(error):
                raise
            last_error = error
            await asyncio.sleep(0.1)

    raise last_error


@pytest.mark.asyncio
async def test_metrics_snapshot_stream_and_all_sandbox_metrics(sandbox_factory):
    sandbox = await sandbox_factory("py-sdk-metrics")
    name = await sandbox.name

    await sandbox.shell("true")

    metrics = await wait_for_metrics(sandbox)
    assert isinstance(metrics.cpu_percent, float)
    assert metrics.memory_limit_bytes > 0
    assert metrics.uptime_ms >= 0
    assert metrics.timestamp_ms > 0

    stream = await sandbox.metrics_stream(0.1)
    streamed = await stream.__anext__()
    assert streamed.memory_limit_bytes > 0

    all_metrics = await all_sandbox_metrics()
    assert name in all_metrics
    assert all_metrics[name].memory_limit_bytes > 0


@pytest.mark.asyncio
async def test_logs_snapshot_filters_and_stream_resume(sandbox_factory):
    sandbox = await sandbox_factory("py-sdk-logs")

    first = await sandbox.shell("echo old-log-line")
    assert first.success is True
    second = await sandbox.shell("echo recent-log-line; echo err-log-line >&2")
    assert second.success is True

    stdout_entries = await sandbox.logs(tail=20, sources=["stdout"])
    stdout_text = "".join(entry.text() for entry in stdout_entries)
    assert "old-log-line" in stdout_text
    assert "recent-log-line" in stdout_text

    stderr_entries = await sandbox.logs(tail=20, sources=["stderr"])
    assert "err-log-line" in "".join(entry.text() for entry in stderr_entries)

    stream = await sandbox.log_stream(sources=["stdout"], follow=False)
    streamed = []
    async for entry in stream:
        streamed.append(entry)

    streamed_text = "".join(entry.text() for entry in streamed)
    assert "recent-log-line" in streamed_text
    assert all(entry.cursor for entry in streamed)

    resumed = await sandbox.log_stream(
        sources=["stdout"],
        from_cursor=streamed[-1].cursor,
        follow=False,
    )
    assert [entry async for entry in resumed] == []

    name = await sandbox.name
    await sandbox.stop()
    handle = await Sandbox.get(name)
    stopped_entries = await handle.logs(tail=20, sources=["stdout"])
    assert "recent-log-line" in "".join(entry.text() for entry in stopped_entries)
