"""Native completion workers must finish while the interpreter is still usable."""

import os
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.parametrize("shutdown", ["explicit", "atexit"])
def test_shutdown_joins_python_completion(tmp_path: Path, shutdown: str) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            r"""
import atexit
import asyncio
import sys
import threading
import time

entered = threading.Event()
release = threading.Event()
finished = threading.Event()
shutdown_started = threading.Event()
loop = asyncio.new_event_loop()
pending = None

def verify():
    # Register before the extension so its exit hook must join the worker first.
    assert finished.is_set(), "native callback survived runtime shutdown"
    assert loop.run_until_complete(pending) == []
    loop.close()
    print("native callback joined before interpreter finalization", flush=True)

atexit.register(verify)
from microsandbox import Snapshot, _microsandbox

original = loop.call_soon_threadsafe
def blocked_completion(*args, **kwargs):
    entered.set()
    assert release.wait(10), "shutdown did not release the GIL for the callback"
    result = original(*args, **kwargs)
    finished.set()
    return result

loop.call_soon_threadsafe = blocked_completion

def release_during_shutdown():
    assert shutdown_started.wait(10), "shutdown never started"
    time.sleep(0.05)
    release.set()

# Start before atexit: Python 3.12 forbids creating threads in exit handlers.
threading.Thread(target=release_during_shutdown, daemon=True).start()

async def prepare():
    global pending
    pending = Snapshot.list()
    assert entered.wait(10), "native completion callback never started"
    assert not finished.is_set()

loop.run_until_complete(prepare())
if sys.argv[1] == "explicit":
    shutdown_started.set()
    _microsandbox._shutdown_runtime()
    assert finished.is_set(), "shutdown returned before joining its callback"
    _microsandbox._shutdown_runtime()  # Closing twice must be harmless.
    async def refuse_new_work():
        try:
            Snapshot.list()
        except RuntimeError as error:
            assert "async runtime has shut down" in str(error)
        else:
            raise AssertionError("restarted the runtime after shutdown")
    loop.run_until_complete(refuse_new_work())
else:
    # LIFO ordering releases the helper just before the SDK's real exit hook.
    atexit.register(shutdown_started.set)
""",
            shutdown,
        ],
        env={
            **os.environ,
            "MSB_HOME": str(tmp_path),
            "MSB_CONFIG_PATH": str(tmp_path / "missing.json"),
        },
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    # Exceptions raised by atexit handlers do not change Python's exit status.
    assert "native callback joined before interpreter finalization" in result.stdout, (
        result.stdout + result.stderr
    )
    assert "Exception ignored" not in result.stderr


def test_shutdown_before_first_operation(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            r"""
import asyncio
from microsandbox import Snapshot, _microsandbox

_microsandbox._shutdown_runtime()
_microsandbox._shutdown_runtime()
async def main():
    try:
        Snapshot.list()
    except RuntimeError as error:
        assert "async runtime has shut down" in str(error)
    else:
        raise AssertionError("initialized a runtime after shutdown")
asyncio.run(main())
""",
        ],
        env={
            **os.environ,
            "MSB_HOME": str(tmp_path),
            "MSB_CONFIG_PATH": str(tmp_path / "missing.json"),
        },
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("_attempt", range(20))
def test_exit_with_pending_native_futures(tmp_path: Path, _attempt: int) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            r"""
import asyncio
import sys
from microsandbox import Snapshot

# Increase interleavings around GIL release, as in the Linux crash reproduction.
sys.setswitchinterval(0.000001)
pending = []
async def main():
    assert await Snapshot.list() == []
    pending.extend(Snapshot.list() for _ in range(200))

asyncio.run(main())
print("asyncio.run completed with pending native work", flush=True)
""",
        ],
        env={
            **os.environ,
            "MSB_HOME": str(tmp_path),
            "MSB_CONFIG_PATH": str(tmp_path / "missing.json"),
        },
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "asyncio.run completed with pending native work" in result.stdout


@pytest.mark.parametrize("cancel", ["cancel", "pending"])
def test_exit_with_open_stdin(tmp_path: Path, cancel: str) -> None:
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            r"""
import atexit
import asyncio
import os
import sys

if os.name == "posix":
    import fcntl
    original = fcntl.fcntl(0, fcntl.F_GETFL)

def verify():
    if os.name == "posix":
        assert fcntl.fcntl(0, fcntl.F_GETFL) == original, "stdin flags were not restored"
    print("stdin shutdown finished", flush=True)

atexit.register(verify)
from microsandbox import Image

pending = None
async def main():
    global pending
    pending = Image.load("-")
    if sys.argv[1] == "cancel":
        try:
            await asyncio.wait_for(pending, timeout=0.2)
        except asyncio.TimeoutError:
            pass
        else:
            raise AssertionError("read unexpectedly finished without input or EOF")
    else:
        await asyncio.sleep(0.2)
        assert not pending.done()

asyncio.run(main())
print("asyncio finished with stdin still open", flush=True)
""",
            cancel,
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={
            **os.environ,
            "MSB_HOME": str(tmp_path),
            "MSB_CONFIG_PATH": str(tmp_path / "missing.json"),
        },
    )
    try:
        # communicate() closes stdin, which would conceal this regression.
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
        pytest.fail(f"interpreter hung with stdin open: {stdout}{stderr}")
    else:
        stdout, stderr = process.communicate()
        assert process.returncode == 0, stdout + stderr
        assert "stdin shutdown finished" in stdout, stdout + stderr
        assert "Exception ignored" not in stderr
