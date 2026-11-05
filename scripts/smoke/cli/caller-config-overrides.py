#!/usr/bin/env python3
"""Verify caller overrides through modify, restart, and live-fork restart.

Set MSB_PATH, MSB_AGENTD_PATH, MSB_LIBKRUNFW_PATH, and CALLER_CONFIG_OVERRIDES_OUT.
The output directory must not exist. Commands use a private MSB_HOME and retain
JSON evidence. Only this suite's sandboxes are stopped during cleanup.
"""

import json
import os
from pathlib import Path
import subprocess


binary = os.environ["MSB_PATH"]
root = Path(os.environ["CALLER_CONFIG_OVERRIDES_OUT"])
root.mkdir(parents=True, exist_ok=False)
env = dict(os.environ, MSB_HOME=str(root / "home"))
image = os.environ.get("MSB_TEST_IMAGE", "docker.io/library/alpine:latest")
rows = []
names = ["layering-source", "layering-child", "layering-batch-a", "layering-batch-b"]
success = False


def run(*args):
    result = subprocess.run(
        [binary, *args], env=env, input="", text=True,
        capture_output=True, timeout=120,
    )
    rows.append({"args": args, "exit": result.returncode,
                 "stdout": result.stdout, "stderr": result.stderr})
    print(json.dumps({"args": args, "exit": result.returncode}), flush=True)
    if result.returncode:
        raise AssertionError(f"{args}: {result.stderr}")
    return result.stdout


def verify(name):
    result = run("exec", "--no-tty", name, "--", "sh", "-ec",
                 'test "$LAYER_VALUE" = updated; test "$PWD" = /; echo overrides-ok')
    assert "overrides-ok" in result
    config = json.loads(run("inspect", name, "--format", "json"))["config"]
    assert any(entry == {"key": "LAYER_VALUE", "value": "updated"}
               for entry in config["env"]), config["env"]
    assert config["runtime"]["workdir"] == "/", config["runtime"]


try:
    run("create", image, "--name", names[0], "--root-disk", "flat:512M",
        "--memory", "256M", "--env", "LAYER_VALUE=original", "--workdir", "/tmp")
    run("modify", names[0], "--env", "LAYER_VALUE=updated", "--workdir", "/",
        "--next-start")
    run("stop", names[0])
    run("start", names[0])
    verify(names[0])

    run("fork", names[0], "--name", names[1])
    verify(names[1])
    run("stop", names[1])
    run("start", names[1])
    verify(names[1])
    run("fork", names[0], "--names", *names[2:])
    for name in names[2:]:
        verify(name)
        run("stop", name)
        run("start", name)
        verify(name)
    success = True
finally:
    cleanup = []
    for name in reversed(names):
        try:
            result = subprocess.run(
                [binary, "stop", name], env=env, input="", text=True,
                capture_output=True, timeout=40,
            )
            cleanup.append({"name": name, "exit": result.returncode,
                            "stderr": result.stderr})
        except (OSError, subprocess.TimeoutExpired) as error:
            cleanup.append({"name": name, "error": str(error)})
    (root / "results.json").write_text(json.dumps(
        {"success": success, "rows": rows, "cleanup": cleanup}, indent=2,
    ))
