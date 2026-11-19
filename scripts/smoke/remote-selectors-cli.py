"""Opt-in remote CLI smoke checks; disposable names only, no account output logged.

Use MSB_REMOTE_SELECTOR_LIVE=1 and --mutate, with MSB_CLI pointing to the build.
The caller supplies MSB_API_KEY/MSB_API_URL; this script never reads key files.
"""
import json
import os
import re
import subprocess
import sys
import uuid
from pathlib import Path

if os.environ.get("MSB_REMOTE_SELECTOR_LIVE") != "1":
    raise SystemExit("Set MSB_REMOTE_SELECTOR_LIVE=1 to opt in")
cli = os.environ.get("MSB_CLI", "msb")
name = "selector-cli-" + uuid.uuid4().hex[:8]
results = []
report = os.environ.get("MSB_SELECTOR_REPORT")


def check(feature, args, expected=None, missing=False):
    try:
        result = subprocess.run([cli, "--remote", *args], check=False, capture_output=True, text=True, timeout=420)
        success = result.returncode == 0
        if expected is not None:
            success = success and expected in result.stdout
        if missing:
            success = result.returncode != 0 and bool(re.search(r"404|not found", result.stderr, re.IGNORECASE))
        row = {"feature": feature, "verdict": "PASS" if success else "FAIL"}
        if not success:
            status = re.search(r"\b[45]\d\d\b", result.stderr)
            row.update(exit=result.returncode, status=status[0] if status else None)
            if "untagged enum CreateRequest" in result.stderr:
                row["reason"] = "configuration_projection_decode"
    except subprocess.TimeoutExpired:
        row = {"feature": feature, "verdict": "FAIL", "reason": "timeout"}
    results.append(row)
    print(json.dumps(row), flush=True)
    if report:
        Path(report).write_text(json.dumps(results, indent=2) + "\n")
    return row["verdict"] == "PASS"


check("cli_sandbox_list", ["list", "--format", "json"])
check("cli_volume_list", ["volume", "list", "--format", "json"])
check("cli_snapshot_list", ["snapshot", "list", "--format", "json"])
if "--mutate" in sys.argv:
    if report:
        Path(report + ".resources.json").write_text(json.dumps({"name": name, "run_name": name + "-run"}) + "\n")
    try:
        check("cli_volume_create", ["volume", "create", name, "--quiet"])
        if check("cli_sandbox_create", ["create", "python", "--name", name, "--quiet"]):
            check("cli_exec", ["exec", name, "--no-stdin", "--", "printf", "selector-cli-ok"], "selector-cli-ok")
        check("cli_run", ["run", "--name", name + "-run", "python", "--", "printf", "selector-run-ok"], "selector-run-ok")
    finally:
        check("cli_sandbox_remove", ["remove", name, "--force", "--quiet"])
        # Named runs persist; cleanup is explicit, including after a failed command.
        check("cli_run_cleanup", ["remove", name + "-run", "--force", "--quiet"])
        check("cli_run_cleanup_verified", ["inspect", name + "-run"], missing=True)
        check("cli_volume_remove", ["volume", "remove", name, "--quiet"])
        check("cli_sandbox_cleanup_verified", ["inspect", name], missing=True)
        check("cli_volume_cleanup_verified", ["volume", "inspect", name], missing=True)
sys.exit(any(row["verdict"] == "FAIL" for row in results))
