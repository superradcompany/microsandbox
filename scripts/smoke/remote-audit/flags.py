"""Read-only live routing checks and negative CLI selection checks."""

import json
import os
import subprocess
from pathlib import Path

assert os.environ.get("MSB_REMOTE_AUDIT") == "1"
rows = []
cli = os.environ["MSB_CLI"]


def check(name, args, backend="local", expected="success", key=True):
    env = dict(os.environ, MSB_BACKEND=backend)
    if not key:
        env.pop("MSB_API_KEY", None)
    result = subprocess.run(
        [cli, *args], env=env, capture_output=True, text=True, timeout=60, check=False
    )
    message = result.stderr.lower()
    ok = result.returncode == 0
    if expected == "remote":
        ok = ok and json.loads(result.stdout)["kind"] == "remote"
    elif expected == "local":
        ok = ok and json.loads(result.stdout)["kind"] == "local"
    elif expected == "conflict":
        ok = result.returncode != 0 and (
            "cannot be used with" in message
            or "cannot be used together" in message
            or "conflict" in message
        )
    elif expected == "missing_key":
        ok = result.returncode != 0 and "msb_api_key" in message
    elif expected == "unsupported_command":
        ok = result.returncode != 0 and (
            "not supported" in message
            or "only supported" in message
            or "apply only" in message
        )
    rows.append(
        {
            "feature": name,
            "verdict": "PASS" if ok else "FAIL",
            "exit": result.returncode,
        }
    )
    print(json.dumps(rows[-1]), flush=True)
    Path(os.environ["MSB_AUDIT_REPORT"]).write_text(
        json.dumps({"sdk": "cli-flags", "rows": rows}, indent=2) + "\n"
    )


check(
    "root_remote_overrides_env_local",
    ["--remote", "context", "--format", "json"],
    expected="remote",
)
check(
    "child_remote_overrides_env_local",
    ["context", "--remote", "--format", "json"],
    expected="remote",
)
check(
    "explicit_local_overrides_env_remote",
    ["--local", "context", "--format", "json"],
    backend="remote",
    expected="local",
)
for backend in ("remote", "cloud"):
    check(
        "ambient_" + backend,
        ["context", "--format", "json"],
        backend=backend,
        expected="remote",
    )
    check(
        "ambient_" + backend + "_live_read",
        ["list", "--format", "json"],
        backend=backend,
    )
for name, args in [
    ("root", ["--remote", "list", "--format", "json"]),
    ("leaf", ["list", "--remote", "--format", "json"]),
    ("group", ["sandbox", "--remote", "list", "--format", "json"]),
    ("alias", ["sbx", "ls", "--remote", "--format", "json"]),
    ("volume", ["volume", "list", "--remote", "--format", "json"]),
    ("plural_volumes", ["volumes", "--remote", "--format", "json"]),
    ("short_volumes", ["vols", "--remote", "--format", "json"]),
    ("snapshot", ["snapshot", "list", "--remote", "--format", "json"]),
    ("plural_snapshots", ["snapshots", "--remote", "--format", "json"]),
]:
    check("routing_" + name, args)
for i, args in enumerate(
    [
        ["--remote", "--local", "list"],
        ["--remote", "list", "--local"],
        ["--local", "sandbox", "list", "--remote"],
        ["volume", "--remote", "list", "--local"],
    ]
):
    check("conflict_" + str(i), args, expected="conflict")
check(
    "missing_remote_credentials",
    ["--remote", "list"],
    expected="missing_key",
    key=False,
)
check(
    "unrelated_command_rejected", ["doctor", "--remote"], expected="unsupported_command"
)
raise SystemExit(any(row["verdict"] == "FAIL" for row in rows))
