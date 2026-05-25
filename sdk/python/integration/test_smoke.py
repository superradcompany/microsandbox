"""End-to-end smoke tests for the Python SDK integration CI lane."""

from __future__ import annotations

import os
import uuid
from contextlib import suppress

import pytest

from microsandbox import Sandbox, Stdin

IMAGE = os.environ.get("MICROSANDBOX_PYTHON_INTEGRATION_IMAGE", "mirror.gcr.io/library/alpine")


def _sandbox_name(prefix: str = "py-sdk-smoke") -> str:
    run_id = os.environ.get("GITHUB_RUN_ID") or str(os.getpid())
    return f"{prefix}-{run_id}-{uuid.uuid4().hex[:8]}"


async def _remove_sandbox(name: str) -> None:
    with suppress(Exception):
        await Sandbox.remove(name)


@pytest.mark.asyncio
async def test_python_sdk_end_to_end_smoke():
    name = _sandbox_name()
    await _remove_sandbox(name)

    sandbox = await Sandbox.create(
        name,
        image=IMAGE,
        cpus=1,
        memory=512,
        replace=True,
    )

    try:
        assert await sandbox.name == name

        output = await sandbox.exec("echo", ["hello"])
        assert output.success is True
        assert output.exit_code == 0
        assert output.stdout_text == "hello\n"
        assert output.stderr_text == ""

        configured = await sandbox.exec(
            "sh",
            ["-c", 'printf "%s:%s\\n" "$(pwd)" "$PYTHON_SMOKE"'],
            cwd="/tmp",
            env={"PYTHON_SMOKE": "ok"},
            timeout=30.0,
        )
        assert configured.success is True
        assert configured.stdout_text == "/tmp:ok\n"

        configured_from_options = await sandbox.exec(
            "sh",
            {
                "args": ["-c", 'printf "%s:%s\\n" "$(pwd)" "$PYTHON_SMOKE"'],
                "cwd": "/tmp",
                "env": {"PYTHON_SMOKE": "dict"},
                "timeout": 30.0,
            },
        )
        assert configured_from_options.success is True
        assert configured_from_options.stdout_text == "/tmp:dict\n"

        shell = await sandbox.shell("printf 'shell:%s\\n' ok")
        assert shell.success is True
        assert shell.stdout_text == "shell:ok\n"

        streamed = await sandbox.exec_stream("sh", ["-c", "echo stream; echo err >&2"])
        streamed_output = await streamed.collect()
        assert streamed_output.success is True
        assert streamed_output.stdout_text == "stream\n"
        assert streamed_output.stderr_text == "err\n"

        streamed_from_options = await sandbox.exec_stream(
            "sh",
            {
                "args": ["-c", "echo stream-options; echo err-options >&2"],
                "timeout": 30.0,
            },
        )
        streamed_options_output = await streamed_from_options.collect()
        assert streamed_options_output.success is True
        assert streamed_options_output.stdout_text == "stream-options\n"
        assert streamed_options_output.stderr_text == "err-options\n"

        stdin_bytes = await sandbox.exec("cat", stdin=Stdin.bytes(b"stdin-bytes\n"))
        assert stdin_bytes.success is True
        assert stdin_bytes.stdout_text == "stdin-bytes\n"

        piped = await sandbox.exec_stream("cat", stdin=Stdin.pipe())
        sink = piped.take_stdin()
        assert sink is not None
        await sink.write(b"stdin-pipe\n")
        await sink.close()
        piped_output = await piped.collect()
        assert piped_output.success is True
        assert piped_output.stdout_text == "stdin-pipe\n"

        fs = sandbox.fs
        await fs.write("/tmp/python-sdk-smoke.txt", b"data\n")
        assert await fs.exists("/tmp/python-sdk-smoke.txt") is True
        assert await fs.exists("/tmp/python-sdk-missing.txt") is False
        assert await fs.read_text("/tmp/python-sdk-smoke.txt") == "data\n"

        metadata = await fs.stat("/tmp/python-sdk-smoke.txt")
        assert metadata.kind == "file"
        assert metadata.size == len(b"data\n")

        metrics = await sandbox.metrics()
        assert isinstance(metrics.cpu_percent, float)
        assert metrics.memory_limit_bytes > 0
    finally:
        with suppress(Exception):
            await sandbox.stop_and_wait()
        await _remove_sandbox(name)


@pytest.mark.asyncio
async def test_python_sdk_create_with_progress_emits_events():
    name = _sandbox_name("py-sdk-progress")
    await _remove_sandbox(name)

    session = Sandbox.create_with_progress(
        name,
        image=IMAGE,
        cpus=1,
        memory=512,
        replace=True,
        pull_policy="always",
    )

    sandbox = None
    try:
        events = []
        async with session:
            async for event in session.progress:
                events.append(event)
            sandbox = await session.result()

        event_types = [event.event_type for event in events]
        assert event_types[0] == "resolving"
        assert "resolved" in event_types
        assert event_types[-1] == "complete"

        resolved = next(event for event in events if event.event_type == "resolved")
        assert resolved.reference
        assert resolved.manifest_digest
        assert resolved.layer_count > 0

        assert await sandbox.name == name
    finally:
        if sandbox is not None:
            with suppress(Exception):
                await sandbox.stop_and_wait()
        await _remove_sandbox(name)
