#!/usr/bin/env python3
"""Bounded Linux real-VMM Stop/eager-activation qualification without product hooks.

Arguments: MSB_BIN AGENTD LIBKRUNFW SDK_TEST_BIN PRELOAD_SO INIT_BIN EXISTING_TEST_HOME.
The home must be a disposable directory containing cached Alpine; all creates use
--pull never. Compile the two adjacent C fixtures and the eager_lifecycle_live SDK
test first. Captured checksums and per-case shim traces remain in the test home.
"""

import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

binary, agent, firmware, sdk_test, preload, init, home_arg = sys.argv[1:]
home = Path(home_arg).resolve()
assert home.parent.name.startswith("msb-customer-fixes."), "disposable session home required"
assert shutil.disk_usage(home).free >= 800_000_000, "retain build/test disk headroom"
run_id = str(os.getpid())
evidence = home / ("stop-activation-" + run_id)
evidence.mkdir()
env = dict(os.environ, MSB_HOME=str(home), MSB_PATH=binary, MSB_AGENTD_PATH=agent,
           MSB_LIBKRUNFW_PATH=firmware)
for key in ["LD_PRELOAD", "MSB_TEST_EAGER_MODE", "MSB_TEST_EAGER_TRACE",
            "MSB_TEST_EAGER_PREFIX", "MSB_TEST_EAGER_DELAY_MS"]:
    env.pop(key, None)
records, owned = [], []
print("EVIDENCE " + str(evidence), flush=True)


def save(record):
    records.append(record)
    (evidence / "results.json").write_text(json.dumps(records, indent=2))
    print(json.dumps(record), flush=True)


def run(*args, check=True, timeout=120, environment=None):
    start = time.monotonic()
    result = subprocess.run([binary, *args], env=environment or env, text=True,
                            capture_output=True, timeout=timeout)
    save(dict(args=args, code=result.returncode, seconds=time.monotonic() - start,
              stdout=result.stdout, stderr=result.stderr))
    if check and result.returncode:
        raise RuntimeError("command failed: " + str(args))
    return result


def create(name, *args):
    assert shutil.disk_usage(home).free >= 600_000_000
    # Refuse name collisions before arming emergency cleanup.
    assert run("inspect", name, "--format", "json", check=False).returncode != 0
    owned.append(name)
    return run("create", "--name", name, "--pull", "never", *args)


def stop_remove(name):
    run("stop", name)
    assert_released(name)
    run("remove", name)
    owned.remove(name)


def wait_path(path, timeout=10):
    deadline = time.monotonic() + timeout
    while not path.exists():
        if time.monotonic() >= deadline:
            raise RuntimeError("missing marker: " + str(path))
        time.sleep(0.02)


def assert_owned(name):
    digest = hashlib.sha256(name.encode()).hexdigest()[:32]
    with (home / "run/locks" / (digest + ".lock")).open("rb") as lease:
        try:
            fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
    raise AssertionError("runtime ownership was released before graceful poweroff")


def assert_released(name):
    # Remove has its own bounded wait; prove Stop released ownership before invoking it.
    digest = hashlib.sha256(name.encode()).hexdigest()[:32]
    with (home / "run/locks" / (digest + ".lock")).open("rb") as lease:
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
    save(dict(args=["ownership_released", name], stdout="PASS immediate nonblocking acquisition"))


def sdk_case(test_name, mode=None, delay=0):
    case_env = dict(env, MSB_PROGRESS_SNAPSHOT="activation-" + run_id + ":baseline")
    if mode:
        trace = evidence / (mode + ".jsonl")
        case_env.update(LD_PRELOAD=preload, MSB_TEST_EAGER_MODE=mode,
                        MSB_TEST_EAGER_DELAY_MS=str(delay), MSB_TEST_EAGER_TRACE=str(trace),
                        MSB_TEST_EAGER_PREFIX=str(home))
    command = [sdk_test, test_name, "--exact", "--ignored", "--nocapture", "--test-threads=1"]
    start = time.monotonic()
    child = subprocess.Popen(command, env=case_env, text=True, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
    names = ([f"eager-{child.pid}-{mode}"] if mode else
             [f"portable-life-{child.pid}-false", f"portable-life-{child.pid}-true"])
    owned.extend(names)
    try:
        stdout, stderr = child.communicate(timeout=120)
    except subprocess.TimeoutExpired:
        # Reap the test runner before finally cleans its exact sandbox names;
        # a stuck runner must not race cleanup by continuing a pending create.
        child.kill()
        stdout, stderr = child.communicate(timeout=10)
        save(dict(args=command, mode=mode, code=child.returncode,
                  seconds=time.monotonic() - start, stdout=stdout, stderr=stderr,
                  error="SDK test safety deadline expired"))
        raise
    save(dict(args=command, mode=mode, code=child.returncode, seconds=time.monotonic() - start,
              stdout=stdout, stderr=stderr))
    if child.returncode:
        raise RuntimeError("SDK live test failed: " + str(mode))
    for name in names:
        owned.remove(name)


def delayed_stop_case(timed):
    label = "timed" if timed else "untimed"
    name = "poweroff-" + run_id + "-" + label
    markers = evidence / label
    markers.mkdir()
    shutil.copy2(init, markers / "delayed-poweroff-init")
    create(name, "alpine", "--memory", "256M", "--max-memory", "256M", "--root-disk", "128M",
           "--no-net", "--volume", str(markers) + ":/test:stat-virt=off",
           "--init", "/test/delayed-poweroff-init", "--init-arg", "12")
    wait_path(markers / "init-ready")
    start = time.monotonic()
    if timed:
        result = run("stop", name, "--timeout", "1", check=False, timeout=10)
        timeout_elapsed = time.monotonic() - start
        assert result.returncode != 0, "one-second stop must time out, not claim completion"
        diagnostic = (result.stdout + result.stderr).lower()
        assert "timed out" in diagnostic and "no kill was requested" in diagnostic
        assert timeout_elapsed < 3, "one-second Stop deadline substantially overran its budget"
        wait_path(markers / "shutdown-requested")
        # The old guest fallback fired at two seconds. Preserve an observation beyond it.
        while time.monotonic() - start < 3.25:
            time.sleep(0.05)
        assert_owned(name)
        assert not (markers / "poweroff").exists()
    run("stop", name, timeout=35)
    assert_released(name)
    elapsed = time.monotonic() - start
    assert elapsed >= 11, "Stop returned before the real guest's delayed poweroff"
    assert (markers / "shutdown-requested").exists()
    assert (markers / "poweroff").exists()
    assert not (markers / "unexpected-sigterm").exists(), "hidden SIGTERM fallback"
    assert not (markers / "reboot-failed").exists()
    run("remove", name)
    owned.remove(name)
    save(dict(args=["delayed_poweroff_result", label], seconds=elapsed, stdout="PASS"))


try:
    source = "activation-source-" + run_id
    create(source, "alpine", "--memory", "256M", "--max-memory", "256M",
           "--root-disk", "128M", "--tmpfs", "/work:16M", "--no-net", "--log-level", "info")
    run("exec", source, "--", "sh", "-ec",
        "dd if=/dev/urandom of=/work/payload bs=1M count=4; sha256sum /work/payload > /work/hash")
    run("snapshot", "create", "baseline", "--group", "activation-" + run_id,
        "--from-sandbox", source, "--full")
    stop_remove(source)
    sdk_case("portable_eager_forked_progress_and_stop_completion")
    sdk_case("eager_preparation_boundary_live", "delay", 15000)
    sdk_case("eager_preparation_boundary_live", "error", 0)
    sdk_case("eager_preparation_boundary_live", "cancel", 45000)
    delayed_stop_case(False)
    delayed_stop_case(True)
    save(dict(args=["summary"], stdout="PASS bounded Stop and eager activation matrix"))
finally:
    # Only an unexpected failure uses Kill for test cleanup, never for successful assertions.
    for name in reversed(owned):
        run("stop", "--force", name, check=False, timeout=45)
    save(dict(args=["disk_free"], stdout=str(shutil.disk_usage(home).free)))
    print("PRESERVED " + str(evidence), flush=True)
