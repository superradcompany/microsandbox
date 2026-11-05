#!/usr/bin/env python3
"""Extra CLI lifecycle checks; requires an isolated MSB_HOME and a running test VM."""

import json
import os
import subprocess
import time

binary = os.environ["MSB_PATH"]
sandbox = os.environ["MSB_JOB_TEST_SANDBOX"]
assert os.environ.get("MSB_HOME")


def run(*args, check=True, data=None):
    p = subprocess.run([binary, *args], input=data, capture_output=True, timeout=30)
    if check and p.returncode:
        raise AssertionError((args, p.returncode, p.stdout, p.stderr))
    return p


def info(job):
    return json.loads(run("inspect", sandbox, "--job", job, "--format", "json").stdout)


def start(*cmd):
    return run("exec", "-d", "--no-tty", sandbox, "--", *cmd).stdout.decode().strip()


def logs(job):
    return run("logs", sandbox, "--job", job).stdout


def until(predicate, seconds=5):
    end = time.monotonic() + seconds
    while not predicate():
        assert time.monotonic() < end, "condition timeout"
        time.sleep(0.05)


# Detached launch must not wait for or consume an open host stdin producer.
p = subprocess.Popen(
    [binary, "exec", "-d", "--no-tty", sandbox, "--", "cat"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)
try:
    assert p.wait(timeout=5) == 0
    job = p.stdout.read().decode().strip()
    assert not info(job)["stdin_closed"]
    run("eof", sandbox, "--job", job)
    run("wait", sandbox, "--job", job)
finally:
    if p.poll() is None:
        p.kill()
    p.communicate(timeout=5)
print("detached launch ignores open host stdin passed", flush=True)
# A waiting client's local timeout leaves the runtime command running.
job = start(
    "sh",
    "-c",
    'trap "echo got-term; exit 23" TERM; echo ready; while :; do sleep .1; done',
)
until(lambda: b"ready" in logs(job))
p = run("wait", sandbox, "--job", job, "--timeout", "100ms", check=False)
assert p.returncode and info(job)["state"] == "running"
run("sandbox", "signal", sandbox, "--job", job, "--signal", "TERM")
p = run("sandbox", "wait", sandbox, "--job", job, "--format", "json", check=False)
assert info(job)["exit_code"] == 23, (p.stdout, p.stderr)
assert b"got-term" in logs(job)
print("wait timeout, signal TERM, exit status and sandbox aliases passed", flush=True)
# Existing sandbox log/inspect commands still select sandbox data by default.
run("exec", "--no-stdin", sandbox, "--", "echo", "ordinary-log-marker")
assert b"ordinary-log-marker" in run("logs", sandbox).stdout
assert json.loads(run("inspect", sandbox, "--format", "json").stdout)["name"] == sandbox
job = start(
    "sh",
    "-c",
    "echo stdout-one; sleep .1; echo stderr-two >&2; sleep .1; echo stdout-three",
)
run("wait", sandbox, "--job", job)
assert (
    run("logs", sandbox, "--job", job, "--source", "stderr").stdout == b"stderr-two\n"
)
assert run("logs", sandbox, "--job", job, "--grep", "three").stdout == b"stdout-three\n"
assert run("logs", sandbox, "--job", job, "--tail", "1").stdout == b"stdout-three\n"
records = [
    json.loads(x)
    for x in run("logs", sandbox, "--job", job, "--json").stdout.splitlines()
]
assert len(records) >= 3
print("sandbox logs unchanged; job source/grep/tail/JSON filters passed", flush=True)
# Kill a host attachment without its destructor. The process and input survive; the lease expires.
job = start("cat")
owner = subprocess.Popen(
    [binary, "attach", sandbox, "--job", job],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)
try:
    owner.stdin.write(b"old-owner\n")
    owner.stdin.flush()
    until(lambda: b"old-owner" in logs(job))
    owner.kill()
    owner.communicate(timeout=5)
    refused = run("attach", sandbox, "--job", job, check=False, data=b"")
    assert refused.returncode and b"input_busy" in refused.stderr, refused.stderr
    time.sleep(32)
    replacement = subprocess.Popen(
        [binary, "attach", sandbox, "--job", job],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        replacement.stdin.write(b"new-owner\n")
        replacement.stdin.close()
        replacement.stdin = None
        until(lambda: b"new-owner" in logs(job))
        assert info(job)["state"] == "running" and not info(job)["stdin_closed"]
        run("eof", sandbox, "--job", job)
        assert replacement.wait(timeout=5) == 0
        run("wait", sandbox, "--job", job)
    finally:
        if replacement.poll() is None:
            replacement.kill()
        replacement.communicate(timeout=5)
finally:
    if owner.poll() is None:
        owner.kill()
        owner.communicate(timeout=5)
    run("kill", sandbox, "--job", job, check=False)
print(
    "abrupt attachment loss, lease expiry, reattach and host EOF semantics passed",
    flush=True,
)
# Refuse launch while paused and stopped; ordinary control remains available.
run("pause", sandbox)
try:
    refused = run("exec", "-d", "--no-tty", sandbox, "--", "true", check=False)
    assert refused.returncode
finally:
    run("resume", sandbox)
run("stop", sandbox)
try:
    refused = run("exec", "-d", "--no-tty", sandbox, "--", "true", check=False)
    assert refused.returncode
    assert (
        json.loads(run("inspect", sandbox, "--format", "json").stdout)["status"]
        == "Stopped"
    )
    assert run("logs", sandbox, "--job", job).stdout == b"old-owner\nnew-owner\n"
finally:
    run("start", sandbox)
print(
    "paused/stopped launch refusals, no implicit restart and offline history passed",
    flush=True,
)
