"""Command execution integration tests."""

from __future__ import annotations

import asyncio
import signal

import pytest

from microsandbox import ExecEventType, ExecTimeoutError, MicrosandboxError, Stdin


@pytest.mark.asyncio
async def test_exec_kwargs_and_options_dict(sandbox_factory):
    sandbox = await sandbox_factory("py-sdk-exec")

    class FakeExecOptions:
        def _to_dict(self):
            return {"args": []}

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

    with pytest.raises(TypeError, match="args must be a list of strings"):
        await sandbox.exec("true", FakeExecOptions())


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

    assert all(isinstance(event.event_type, ExecEventType) for event in events)
    assert any(event.event_type is ExecEventType.STARTED and event.pid for event in events)
    stdout = b"".join(
        event.data or b"" for event in events if event.event_type is ExecEventType.STDOUT
    )
    stderr = b"".join(
        event.data or b"" for event in events if event.event_type is ExecEventType.STDERR
    )
    assert stdout == b"stream\n"
    assert stderr == b"err\n"
    assert [event.code for event in events if event.event_type is ExecEventType.EXITED] == [7]

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
    assert first.event_type is ExecEventType.STARTED
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
        if event.event_type is ExecEventType.STDOUT and b"ready" in (event.data or b""):
            break

    pending_event = asyncio.ensure_future(handle.recv())
    await asyncio.wait_for(handle.resize(40, 100), timeout=5)
    await stdin.write(b"continue\n")

    events = [await pending_event]
    events.extend([event async for event in handle])
    output = b"".join(
        event.data or b"" for event in events if event and event.event_type is ExecEventType.STDOUT
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
    saw_started = any(event.event_type is ExecEventType.STARTED for event in events)
    saw_failed = any(event.event_type is ExecEventType.FAILED for event in events)
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

    with pytest.raises(TypeError, match="stdin must be Stdin"):
        await sandbox.exec("true", stdin="null")


@pytest.mark.asyncio
async def test_empty_stdin_write_keeps_stdin_open(sandbox_factory):
    sandbox = await sandbox_factory("py-sdk-stdin-empty")

    piped = await sandbox.exec_stream("cat", stdin=Stdin.pipe())
    sink = piped.take_stdin()
    assert sink is not None

    await sink.write(b"aaaaa")
    await sink.write(b"")
    await sink.write(b"bbbbb")
    await sink.close()

    await sink.write(b"")
    with pytest.raises(MicrosandboxError, match="stdin closed"):
        await sink.write(b"after EOF")

    output = await piped.collect()
    assert output.success is True
    assert output.stdout_text == "aaaaabbbbb"


@pytest.mark.asyncio
async def test_rlimits_reject_raw_dicts(sandbox_factory):
    sandbox = await sandbox_factory("py-sdk-rlimit-types")

    with pytest.raises(TypeError, match="rlimit must be Rlimit"):
        await sandbox.exec(
            "true",
            rlimits=[{"resource": "cpu", "soft": 1, "hard": 1}],
        )


@pytest.mark.asyncio
async def test_exec_stream_backpressure_preserves_output(sandbox_factory):
    sandbox = await sandbox_factory("py-sdk-backpressure")
    command = (
        "head -c 16777216 /dev/zero; "
        "head -c 16777216 /dev/zero >&2; touch /tmp/output-complete"
    )
    handle = await sandbox.exec_stream("sh", ["-c", command])
    started = await asyncio.wait_for(handle.recv(), 5)
    assert started.event_type is ExecEventType.STARTED

    # Leave enough time for this finite producer to finish without backpressure.
    # It must instead remain alive and wait for the reader.
    await asyncio.sleep(5)
    probe = await sandbox.exec(
        "sh", ["-c", f"test -d /proc/{started.pid} && test ! -e /tmp/output-complete"], timeout=3
    )
    assert probe.exit_code == 0

    async def consume():
        sizes = {ExecEventType.STDOUT: 0, ExecEventType.STDERR: 0}
        codes = []
        async for event in handle:
            if event.event_type in sizes:
                assert not any(event.data)
                sizes[event.event_type] += len(event.data)
            elif event.event_type is ExecEventType.EXITED:
                codes.append(event.code)
        return sizes, codes

    sizes, codes = await asyncio.wait_for(consume(), 30)
    assert sizes == {ExecEventType.STDOUT: 16777216, ExecEventType.STDERR: 16777216}
    assert codes == [0]
    assert (await sandbox.exec("test", ["-e", "/tmp/output-complete"])).exit_code == 0

    # A large pending stdin write must not trap the output credits behind it.
    handle = await sandbox.exec_stream("cat", stdin=Stdin.pipe())
    assert (await asyncio.wait_for(handle.recv(), 5)).event_type is ExecEventType.STARTED
    sink = handle.take_stdin()

    async def write():
        for _ in range(1024):
            await sink.write(bytes(65536))
        await sink.close()

    writer = asyncio.create_task(write())
    try:
        await asyncio.sleep(1)
        assert not writer.done()
        (sizes, codes), _ = await asyncio.wait_for(asyncio.gather(consume(), writer), 60)
        assert sizes == {ExecEventType.STDOUT: 67108864, ExecEventType.STDERR: 0}
        assert codes == [0]
    finally:
        writer.cancel()
        await asyncio.gather(writer, return_exceptions=True)
