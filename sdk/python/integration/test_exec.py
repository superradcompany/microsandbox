"""Command execution integration tests."""

from __future__ import annotations

import asyncio
import signal

import pytest

from microsandbox import ExecTimeoutError, MicrosandboxError, Stdin


@pytest.mark.asyncio
async def test_exec_kwargs_and_options_dict(sandbox_factory):
    sandbox = await sandbox_factory("py-sdk-exec")

    output = await sandbox.exec("echo", ["hello"])
    assert output.success is True
    assert output.exit_code == 0
    assert output.stdout_text == "hello\n"
    assert output.stderr_text == ""
    assert output.stdout_bytes == b"hello\n"

    non_zero = await sandbox.exec("sh", ["-c", "echo nope >&2; exit 42"])
    assert non_zero.success is False
    assert non_zero.exit_code == 42
    assert non_zero.stderr_text == "nope\n"

    configured_with_kwargs = await sandbox.exec(
        "sh",
        ["-c", 'printf "%s:%s\\n" "$(pwd)" "$PYTHON_SMOKE"'],
        cwd="/tmp",
        env={"PYTHON_SMOKE": "kwargs"},
        timeout=30.0,
    )
    assert configured_with_kwargs.success is True
    assert configured_with_kwargs.stdout_text == "/tmp:kwargs\n"

    configured_with_options = await sandbox.exec(
        "sh",
        {
            "args": ["-c", 'printf "%s:%s\\n" "$(pwd)" "$PYTHON_SMOKE"'],
            "cwd": "/tmp",
            "env": {"PYTHON_SMOKE": "dict"},
            "timeout": 30.0,
        },
    )
    assert configured_with_options.success is True
    assert configured_with_options.stdout_text == "/tmp:dict\n"

    with pytest.raises(TypeError, match="unknown exec option"):
        await sandbox.exec("true", {"args": [], "typo": True})


@pytest.mark.asyncio
async def test_shell_timeout_and_user_env_overrides(sandbox_factory):
    sandbox = await sandbox_factory("py-sdk-exec-opts", env={"BASE_VAR": "base"})

    out = await sandbox.shell(
        'printf "%s:%s\\n" "$(whoami)" "$BASE_VAR:$EXEC_VAR"',
        user="nobody",
        env={"EXEC_VAR": "exec"},
    )
    assert out.success is True
    assert out.stdout_text == "nobody:base:exec\n"

    with pytest.raises(ExecTimeoutError):
        await sandbox.shell("sleep 60", timeout=0.2)


@pytest.mark.asyncio
async def test_exec_stream_iteration_collect_wait_and_signal(sandbox_factory):
    sandbox = await sandbox_factory("py-sdk-stream")

    handle = await sandbox.exec_stream("sh", ["-c", "echo stream; echo err >&2; exit 7"])
    assert handle.id
    events = []
    async for event in handle:
        events.append(event)

    assert any(event.event_type == "started" and event.pid for event in events)
    stdout = b"".join(event.data or b"" for event in events if event.event_type == "stdout")
    stderr = b"".join(event.data or b"" for event in events if event.event_type == "stderr")
    assert stdout == b"stream\n"
    assert stderr == b"err\n"
    assert [event.code for event in events if event.event_type == "exited"] == [7]

    collect_handle = await sandbox.exec_stream(
        "sh",
        {"args": ["-c", "echo collected; echo collected-err >&2"], "timeout": 30.0},
    )
    collected = await collect_handle.collect()
    assert collected.success is True
    assert collected.stdout_text == "collected\n"
    assert collected.stderr_text == "collected-err\n"

    kwargs_handle = await sandbox.exec_stream(
        "sh",
        ["-c", "echo stream-kwargs; echo stream-kwargs-err >&2"],
        timeout=30.0,
    )
    kwargs_output = await kwargs_handle.collect()
    assert kwargs_output.success is True
    assert kwargs_output.stdout_text == "stream-kwargs\n"
    assert kwargs_output.stderr_text == "stream-kwargs-err\n"

    sleep_handle = await sandbox.shell_stream("sleep 60")
    first = await sleep_handle.recv()
    assert first is not None
    assert first.event_type == "started"
    await sleep_handle.signal(signal.SIGTERM)
    code, success = await sleep_handle.wait()
    assert success is False
    assert code != 0


@pytest.mark.asyncio
async def test_exec_stream_tty_resize_while_receiving(sandbox_factory):
    sandbox = await sandbox_factory("py-sdk-tty-resize")

    handle = await sandbox.shell_stream(
        "printf 'ready\\n'; read value; stty size",
        stdin=Stdin.pipe(),
        tty=True,
    )
    stdin = handle.take_stdin()
    assert stdin is not None

    while True:
        event = await handle.recv()
        assert event is not None
        if event.event_type == "stdout" and b"ready" in (event.data or b""):
            break

    pending_event = asyncio.ensure_future(handle.recv())
    await asyncio.wait_for(handle.resize(40, 100), timeout=5)
    await stdin.write(b"continue\n")

    events = [await pending_event]
    events.extend([event async for event in handle])
    output = b"".join(
        event.data or b"" for event in events if event and event.event_type == "stdout"
    )
    assert b"40 100" in output


@pytest.mark.asyncio
async def test_exec_stream_missing_binary_surfaces_failure(sandbox_factory):
    sandbox = await sandbox_factory("py-sdk-stream-fail")

    try:
        handle = await sandbox.exec_stream("/no/such/binary-python-sdk")
    except MicrosandboxError:
        return

    events = [event async for event in handle]
    saw_started = any(event.event_type == "started" for event in events)
    saw_failed = any(event.event_type == "failed" for event in events)
    assert saw_failed or not saw_started


@pytest.mark.asyncio
async def test_stdin_modes_and_take_stdin_contract(sandbox_factory):
    sandbox = await sandbox_factory("py-sdk-stdin")

    no_pipe = await sandbox.exec_stream("echo", ["hi"])
    assert no_pipe.take_stdin() is None
    assert (await no_pipe.collect()).stdout_text == "hi\n"

    stdin_bytes = await sandbox.exec("cat", stdin=Stdin.bytes(b"stdin-bytes\n"))
    assert stdin_bytes.success is True
    assert stdin_bytes.stdout_text == "stdin-bytes\n"

    piped = await sandbox.exec_stream("cat", stdin=Stdin.pipe())
    sink = piped.take_stdin()
    assert sink is not None
    assert piped.take_stdin() is None
    await sink.write(b"stdin-pipe\n")
    await sink.close()
    piped_output = await piped.collect()
    assert piped_output.success is True
    assert piped_output.stdout_text == "stdin-pipe\n"
