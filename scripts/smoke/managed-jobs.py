#!/usr/bin/env python3
"""Managed-job CLI smoke test against an explicitly selected disposable running VM."""

import json
import os
import queue
import selectors
import subprocess
import sys
import threading
import time
from pathlib import Path

root = Path(__file__).resolve().parents[2]
env = os.environ.copy()
sandbox = os.environ["MSB_JOB_TEST_SANDBOX"]
# Require an explicitly selected disposable home; never use the user's default home.
assert os.environ.get("MSB_HOME"), "set an isolated MSB_HOME for this smoke test"
binary = os.environ.get("MSB_PATH", str(root / "target/debug/msb"))


def run(*args, check=True, input=None):
    p = subprocess.run(
        [binary, *args],
        env=env,
        input=input,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=20,
    )
    if check and p.returncode:
        raise RuntimeError((args, p.returncode, p.stdout, p.stderr))
    return p


job = (
    run(
        "exec",
        "-d",
        "--no-tty",
        sandbox,
        "--",
        "sh",
        "-c",
        'n=0; while true; do n=$((n + 1)); echo "$n"; sleep 0.1; done',
    )
    .stdout.decode()
    .strip()
)
print("created", job, flush=True)
assert job.startswith("job_")
time.sleep(0.4)
before = run("logs", sandbox, "--job", job).stdout
assert before.strip(), before
run("pause", sandbox)
paused = run("logs", sandbox, "--job", job).stdout
time.sleep(0.4)
assert run("logs", sandbox, "--job", job).stdout == paused
run("resume", sandbox)
time.sleep(0.4)
after = run("logs", sandbox, "--job", job).stdout
assert len(after) > len(paused), (paused, after)
run("kill", sandbox, "--job", job)
info = json.loads(run("inspect", sandbox, "--job", job, "--format", "json").stdout)
wait = run("wait", sandbox, "--job", job, check=False)
assert wait.returncode != 0
print("pause/resume and kill passed", wait.returncode, flush=True)
cat = run("exec", "-d", "--no-tty", sandbox, "--", "cat").stdout.decode().strip()
run("eof", sandbox, "--job", cat)
assert run("wait", sandbox, "--job", cat).returncode == 0
print("retained stdin + EOF passed", flush=True)
noinput = run("exec", "-d", "--no-stdin", sandbox, "--", "cat").stdout.decode().strip()
run("wait", sandbox, "--job", noinput)
print("closed stdin passed", flush=True)
missing = run(
    "exec", "-d", "--no-tty", sandbox, "--", "/no-such-managed-job", check=False
)
assert missing.returncode != 0
print("spawn failure passed", missing.stderr.decode().strip(), flush=True)
ordinary = run(
    "exec", "--no-tty", sandbox, "--", "cat", input=b"ordinary stdin regression\n"
)
assert ordinary.stdout == b"ordinary stdin regression\n"
print("ordinary exec stdin passed", flush=True)

# A producer may keep its pipe open while waiting for the guest's first response.
process = subprocess.Popen(
    [
        binary,
        "exec",
        "--stream",
        sandbox,
        "--",
        "sh",
        "-c",
        'echo ready; read value; echo "$value"',
    ],
    env=env,
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)
try:
    # Windows selectors accept sockets, not anonymous subprocess pipes. A bounded reader
    # also lets this regression exercise real native Windows stdin without polling EOF.
    ready = queue.Queue()
    threading.Thread(
        target=lambda: ready.put(process.stdout.readline()), daemon=True
    ).start()
    assert ready.get(timeout=5) == b"ready\n", (
        "exec waited for host EOF before starting the command"
    )
    process.stdin.write(b"open producer\n")
    process.stdin.flush()
    assert process.wait(timeout=5) == 0, (
        "exec waited for the open host pipe after guest exit"
    )
    assert process.stdout.read() == b"open producer\n"
finally:
    if process.poll() is None:
        process.kill()
    process.communicate(timeout=5)
print("open-producer stdin startup and shutdown regression passed", flush=True)

# Full captures must refuse before pausing or publishing an unattachable execution.
guarded = (
    run("exec", "-d", "--no-tty", sandbox, "--", "sleep", "30").stdout.decode().strip()
)
try:
    captures = [
        ("snap", "create", "managed-job-guard", "--sandbox", sandbox, "--full"),
        ("fork", sandbox, "--name", "managed-job-guard-child"),
    ]
    for paused in [False, True]:
        if paused:
            run("pause", sandbox)
        try:
            for command in captures:
                refused = run(*command, check=False)
                assert refused.returncode != 0, command
                assert b"managed jobs are active" in refused.stderr, refused.stderr
                assert b"wait for or terminate those jobs first" in refused.stderr, refused.stderr
            # The refusal must preserve both the job and the source's resident pause state.
            state = json.loads(run("inspect", sandbox, "--format", "json").stdout)["status"]
            assert state == ("Paused" if paused else "Running"), state
            info = json.loads(run("inspect", sandbox, "--job", guarded, "--format", "json").stdout)
            assert info["state"] == "running", info
            waiting = run("wait", sandbox, "--job", guarded, "--timeout", "100ms", check=False)
            assert waiting.returncode and b"timed out" in waiting.stderr, waiting.stderr
        finally:
            if paused:
                run("resume", sandbox)
    assert run("exec", "--no-stdin", sandbox, "--", "true").returncode == 0
finally:
    run("kill", sandbox, "--job", guarded, check=False)
    run("wait", sandbox, "--job", guarded, check=False)
print("full snapshot and fork safeguards passed", flush=True)

if os.name == "posix":
    import platform
    import shlex
    import shutil

    script = shutil.which("script")
    assert script, "the terminal smoke test requires the script utility"
    terminal_job = (
        run("exec", "-d", "--tty", sandbox, "--", "sh").stdout.decode().strip()
    )
    try:
        # script establishes a real controlling terminal on both macOS and Linux. Reopening a
        # slave in the parent after TIOCSCTTY is not portable across their terminal drivers.
        for marker in [b"first-attachment", b"second-attachment"]:
            command = [binary, "attach", sandbox, "--job", terminal_job]
            if platform.system() == "Darwin":
                command = [script, "-q", "/dev/null", *command]
            else:
                command = [script, "-q", "-e", "-c", shlex.join(command), "/dev/null"]
            attached = subprocess.Popen(
                command,
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                # Send a split marker so terminal echo alone cannot satisfy the assertion.
                attached.stdin.write(
                    b"printf '%s%s\\n' " + marker[:6] + b" " + marker[6:] + b"\n"
                )
                attached.stdin.flush()
                with selectors.DefaultSelector() as ready:
                    ready.register(attached.stdout, selectors.EVENT_READ)
                    output = b""
                    while marker not in output:
                        assert ready.select(5), ("no terminal output", output)
                        data = os.read(attached.stdout.fileno(), 8192)
                        assert data, ("terminal attachment exited", output)
                        output += data
                attached.stdin.write(b"\x1d")
                attached.stdin.flush()
                assert attached.wait(timeout=5) == 0
                info = json.loads(
                    run(
                        "inspect", sandbox, "--job", terminal_job, "--format", "json"
                    ).stdout
                )
                assert info["state"] == "running"
            finally:
                if attached.poll() is None:
                    attached.kill()
                attached.communicate(timeout=5)
    finally:
        run("kill", sandbox, "--job", terminal_job, check=False)
        run("wait", sandbox, "--job", terminal_job, check=False)
    print("CLI terminal input, Ctrl-] detach and reattach passed", flush=True)
    subprocess.run(
        [sys.executable, str(root / "scripts/smoke/managed-job-terminal.py")],
        env=env,
        check=True,
        timeout=90,
    )

if os.environ.get("MSB_JOB_TEST_RESTART") == "1":
    completed = (
        run("exec", "-d", "--no-stdin", sandbox, "--", "echo", "retained-history")
        .stdout.decode()
        .strip()
    )
    run("wait", sandbox, "--job", completed)
    pending = (
        run(
            "exec",
            "-d",
            "--no-tty",
            sandbox,
            "--",
            "sh",
            "-c",
            "echo started-once; sleep 30",
        )
        .stdout.decode()
        .strip()
    )
    deadline = time.monotonic() + 5
    while not run("logs", sandbox, "--job", pending).stdout:
        assert time.monotonic() < deadline, "job did not produce initial output"
        time.sleep(0.05)
    retained = run("logs", sandbox, "--job", pending).stdout
    run("stop", sandbox)
    try:
        assert run("logs", sandbox, "--job", completed).stdout == b"retained-history\n"
        run("wait", sandbox, "--job", completed)
        lost = json.loads(
            run("inspect", sandbox, "--job", pending, "--format", "json").stdout
        )
        assert lost["state"] == "lost" and lost["exit_code"] is None
    finally:
        run("start", sandbox)
    lost = json.loads(
        run("inspect", sandbox, "--job", pending, "--format", "json").stdout
    )
    assert lost["state"] == "lost" and lost["exit_code"] is None
    assert run("logs", sandbox, "--job", pending).stdout == retained
    print("retained history and restart without reexecution passed", flush=True)
