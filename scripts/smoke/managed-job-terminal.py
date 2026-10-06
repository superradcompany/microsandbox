#!/usr/bin/env python3
"""Real Unix terminal regressions against an explicitly selected disposable VM."""

import fcntl
import json
import os
import selectors
import signal
import subprocess
import tempfile
import termios
import time


assert os.name == "posix", "Windows uses the native console/ConPTY validation harness"
assert os.environ.get("MSB_HOME"), "select an isolated disposable MSB_HOME"
binary = os.environ["MSB_PATH"]
sandbox = os.environ["MSB_JOB_TEST_SANDBOX"]


def run(*args, check=True):
    result = subprocess.run(
        [binary, *args], capture_output=True, timeout=20, check=False
    )
    if check and result.returncode:
        raise AssertionError((args, result.returncode, result.stdout, result.stderr))
    return result


def launch(*command):
    return run("exec", "-d", "--no-tty", sandbox, "--", *command).stdout.decode().strip()


def info(job):
    return json.loads(run("inspect", sandbox, "--job", job, "--format", "json").stdout)


def terminal(job, data, success=True):
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
        offset = 0
        with selectors.DefaultSelector() as events:
            events.register(master, selectors.EVENT_READ | selectors.EVENT_WRITE)
            while status is None:
                for _, ready in events.select(0.1):
                    if ready & selectors.EVENT_WRITE and offset < len(data):
                        try:
                            offset += os.write(master, data[offset : offset + 8192])
                        except BlockingIOError:
                            pass
                    if ready & selectors.EVENT_READ:
                        try:
                            output.extend(os.read(master, 16384))
                        except BlockingIOError:
                            pass
                observed, value = os.waitpid(pid, os.WNOHANG)
                if observed:
                    status = value
                assert time.monotonic() - started < 25, "terminal attachment hung"
        report = json.loads(os.read(report_read, 4096))
        assert report["restored"], "host terminal modes were not restored"
        code = report["code"]
        if success:
            assert code == 0, (code, bytes(output)[-2000:])
            assert offset == len(data), (offset, len(data))
        else:
            assert code != 0 and b"input_not_flushed" in output, (code, bytes(output)[-2000:])
            assert time.monotonic() - started < 6, "failed drain did not return promptly"
        return bytes(output)
    finally:
        if status is None:
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


for payload in [b"same-read prefix\n", b"large paste remains ordered\n" * 8192]:
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

for paused in [False, True]:
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
