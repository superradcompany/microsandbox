"""End-to-end smoke tests for the Python SDK integration CI lane."""

from __future__ import annotations

import os
import uuid
from contextlib import suppress

import pytest

from microsandbox import Sandbox

IMAGE = os.environ.get("MICROSANDBOX_PYTHON_INTEGRATION_IMAGE", "mirror.gcr.io/library/alpine")


def _sandbox_name() -> str:
    run_id = os.environ.get("GITHUB_RUN_ID") or str(os.getpid())
    return f"py-sdk-smoke-{run_id}-{uuid.uuid4().hex[:8]}"


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

        shell = await sandbox.shell("printf 'shell:%s\\n' ok")
        assert shell.success is True
        assert shell.stdout_text == "shell:ok\n"

        streamed = await sandbox.exec_stream("sh", ["-c", "echo stream; echo err >&2"])
        streamed_output = await streamed.collect()
        assert streamed_output.success is True
        assert streamed_output.stdout_text == "stream\n"
        assert streamed_output.stderr_text == "err\n"

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
