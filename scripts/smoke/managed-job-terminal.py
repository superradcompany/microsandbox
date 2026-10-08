#!/usr/bin/env python3
"""Real Unix terminal regressions against an explicitly selected disposable VM."""

import argparse
import errno
import fcntl
import json
import os
import select
import selectors
import signal
import subprocess
import tempfile
import termios
import time
import tty


assert os.name == "posix", "Windows uses the native console/ConPTY validation harness"
assert os.environ.get("MSB_HOME"), "select an isolated disposable MSB_HOME"
binary = os.environ["MSB_PATH"]
sandbox = os.environ["MSB_JOB_TEST_SANDBOX"]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--backpressure-only", action="store_true")
parser.add_argument("--tty-only", action="store_true")
args = parser.parse_args()


def run(*args, check=True):
    result = subprocess.run(
        [binary, *args], capture_output=True, timeout=20, check=False
    )
    if check and result.returncode:
        raise AssertionError((args, result.returncode, result.stdout, result.stderr))
    return result


def launch(*command, tty=False):
    return run("exec", "-d", "--tty" if tty else "--no-tty", sandbox, "--", *command).stdout.decode().strip()


def info(job):
    return json.loads(run("inspect", sandbox, "--job", job, "--format", "json").stdout)


def terminal(job, data, success=True, failure_reason=None, overflow=False):
    """Check input, restored modes and bounded detach; None allows incomplete admission."""
    master, slave = os.openpty()
    report_read, report_write = os.pipe()
    original = termios.tcgetattr(slave)
    pid = os.fork()
    if pid == 0:
        os.close(report_read)
        os.close(master)
        os.login_tty(slave)
        # Keep the controlling session alive until modes have been inspected: macOS invalidates
        # the parent's slave descriptor when its controlling session leader exits.
        result = subprocess.run([binary, "attach", sandbox, "--job", job], check=False)
        report = {"code": result.returncode, "restored": termios.tcgetattr(0) == original}
        if overflow:
            # Model a shell line editor's next read without flushing or executing any bytes.
            tty.setcbreak(0, termios.TCSANOW)
            unread = os.read(0, 128) if select.select([0], [], [], 0.1)[0] else b""
            report["unread_paste"] = unread.hex()
        os.write(report_write, json.dumps(report).encode())
        os._exit(0)
    os.close(report_write)
    status = None
    output = bytearray()
    started = time.monotonic()
    try:
        # Keep the original slave descriptor: reopening it after TIOCSCTTY is not portable.
        # Wait for actual raw mode before writing, so canonical echo cannot mask lost input.
        while termios.tcgetattr(slave)[3] & termios.ICANON:
            observed, value = os.waitpid(pid, os.WNOHANG)
            if observed:
                status = value
            assert not observed, "attachment exited before entering raw mode"
            assert time.monotonic() - started < 10, "terminal never entered raw mode"
            time.sleep(0.01)
        fcntl.fcntl(master, fcntl.F_SETFL, os.O_NONBLOCK)
        input_started = time.monotonic()
        offset = 0
        input_open = True
        write_limit = len(data) - 1 if overflow else len(data)
        paste_sent = None
        shortcut_sent = None
        with selectors.DefaultSelector() as events:
            events.register(master, selectors.EVENT_READ | selectors.EVENT_WRITE)
            while status is None:
                for _, ready in events.select(0.1):
                    if ready & selectors.EVENT_WRITE and input_open and offset < write_limit:
                        try:
                            offset += os.write(master, data[offset : min(offset + 8192, write_limit)])
                            if offset == len(data):
                                shortcut_sent = time.monotonic()
                        except BlockingIOError:
                            # PTY readiness can race; retry this nonblocking write on the next tick.
                            pass
                        except OSError as error:
                            if error.errno != errno.EIO:
                                raise
                            # A guest exit or connection failure can end input before all bytes
                            # are sent. Keep the real count and verify the result and modes.
                            input_open = False
                            events.modify(master, selectors.EVENT_READ)
                    if ready & selectors.EVENT_READ:
                        try:
                            output.extend(os.read(master, 16384))
                        except BlockingIOError:
                            # A readiness notification may outlive the available PTY bytes.
                            pass
                        except OSError as error:
                            if error.errno != errno.EIO:
                                raise
                            events.unregister(master)
                if overflow and offset == len(data) - 1:
                    if paste_sent is None:
                        paste_sent = time.monotonic()
                    if b"attachment remains open" in output and time.monotonic() - paste_sent > 0.25:
                        assert termios.tcgetattr(slave)[3] & termios.ICANON == 0
                        write_limit = len(data)
                observed, value = os.waitpid(pid, os.WNOHANG)
                if observed:
                    status = value
                    assert not overflow or shortcut_sent is not None, "overflow detached before Ctrl-]"
                assert time.monotonic() - input_started < (25 if success or overflow else 8), "terminal attachment hung"
        report = json.loads(os.read(report_read, 4096))
        assert report["restored"], "host terminal modes were not restored"
        if overflow:
            assert report["unread_paste"] == "", report
            assert offset == len(data), (offset, len(data))
            assert bytes(output).count(b"[input_not_flushed:") == 1, bytes(output)[-2000:]
        code = report["code"]
        if code == 0:
            assert success is not False, (code, bytes(output)[-2000:])
            assert offset == len(data), (offset, len(data))
        else:
            assert success is not True and b"input_not_flushed" in output, (code, bytes(output)[-2000:])
            if failure_reason is not None:
                assert failure_reason in output, bytes(output)[-2000:]
        if success is not True:
            detach_started = shortcut_sent if overflow else input_started
            assert time.monotonic() - detach_started < 6, "backpressured attachment did not return promptly"
        return bytes(output)
    finally:
        if status is None:
            observed, status = os.waitpid(pid, os.WNOHANG)
            if not observed:
                os.killpg(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
        os.close(master)
        os.close(slave)
        os.close(report_read)


def saturate(job):
    # A file avoids a harness thread blocked in a pipe write. Its shared offset shows when
    # the CLI stops reading after guest/runtime input admission becomes backpressured.
    with tempfile.TemporaryFile() as source:
        source.write(b"x" * (8 * 1024 * 1024))
        source.seek(0)
        process = subprocess.Popen(
            [binary, "attach", sandbox, "--job", job],
            stdin=source,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            last = -1
            stable = time.monotonic()
            deadline = stable + 15
            while True:
                assert process.poll() is None, process.communicate()
                position = source.tell()
                if position != last:
                    last, stable = position, time.monotonic()
                if position > 0 and time.monotonic() - stable > 0.5:
                    break
                assert time.monotonic() < deadline, "input did not saturate"
                time.sleep(0.05)
            process.send_signal(signal.SIGINT)
            output, error = process.communicate(timeout=5)
            assert process.returncode == 0, (output, error)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=5)


for payload in ([] if args.backpressure_only or args.tty_only else [b"same-read prefix\n", b"large paste remains ordered\n" * 8192]):
    job = launch("cat")
    try:
        terminal(job, payload + b"\x1d")
        assert info(job)["state"] == "running" and not info(job)["stdin_closed"]
        run("eof", sandbox, "--job", job)
        run("wait", sandbox, "--job", job)
        assert run("logs", sandbox, "--job", job).stdout == payload
    finally:
        run("kill", sandbox, "--job", job, check=False)
    print("terminal prefix preserved", len(payload), flush=True)

for paused in ([] if args.backpressure_only or args.tty_only else [False, True]):
    job = launch("sleep", "120")
    try:
        if paused:
            run("pause", sandbox)
        saturate(job)
        terminal(job, b"pending\n\x1d", success=False)
        assert info(job)["state"] == "running" and not info(job)["stdin_closed"]
        # A second attachment proves that failure still released the input lease.
        terminal(job, b"\x1d")
    finally:
        if paused:
            run("resume", sandbox)
        run("kill", sandbox, "--job", job, check=False)
        run("wait", sandbox, "--job", job, check=False)
    print("bounded incomplete drain and reattach", "paused" if paused else "non-reading", flush=True)

# Fill the terminal adapter's own queue on this attachment, rather than only filling the
# runtime through an earlier attachment. This catches shortcut reads gated by writer capacity.
for overflow in ([] if args.tty_only else [False, True]):
    for paused in [False, True]:
        job = launch("sleep", "120")
        try:
            if paused:
                run("pause", sandbox)
            payload = b"x" * (8 * 1024 * 1024 if overflow else 512 * 1024)
            # A small burst may fit in runtime custody without the guest consuming it. Either
            # a complete drain or an explicit incomplete drain must return promptly; overflow
            # reports loss but stays attached until an explicit shortcut, consuming the remaining
            # paste instead of returning it to the host shell.
            terminal(job, payload + b"\x1d", success=False if overflow else None,
                     failure_reason=b"lookahead" if overflow else b"two seconds", overflow=overflow)
            assert info(job)["state"] == "running" and not info(job)["stdin_closed"]
            terminal(job, b"\x1d")
        finally:
            if paused:
                run("resume", sandbox)
            run("kill", sandbox, "--job", job, check=False)
            run("wait", sandbox, "--job", job, check=False)
        print("same attachment overflow" if overflow else "same attachment Ctrl-] under backpressure",
              "paused" if paused else "non-reading", flush=True)

# Guest raw mode prevents canonical-line dropping and echo from masking a blocked input writer.
# This also exercises initial resize and attachment cleanup with a real guest PTY.
for paused in [False, True]:
    job = launch("sh", "-c", "stty raw -echo && printf 'tty-ready\\n' && sleep 120", tty=True)
    try:
        ready_deadline = time.monotonic() + 10
        while b"tty-ready" not in run("logs", sandbox, "--job", job).stdout:
            assert time.monotonic() < ready_deadline, "guest PTY did not enter raw mode"
            time.sleep(0.02)
        if paused:
            run("pause", sandbox)
        terminal(job, b"x" * (512 * 1024) + b"\x1d", success=None,
                 failure_reason=b"two seconds")
        state = info(job)
        assert state["tty"] and state["state"] == "running" and not state["stdin_closed"]
        terminal(job, b"\x1d")
    finally:
        if paused:
            run("resume", sandbox)
        run("kill", sandbox, "--job", job, check=False)
        run("wait", sandbox, "--job", job, check=False)
    print("PTY same attachment Ctrl-]", "paused" if paused else "non-reading", flush=True)
