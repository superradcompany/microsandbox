"""Opt-in command-by-command --remote audit; never touch pre-existing resources."""

import json
import os
import re
import subprocess
import uuid
from pathlib import Path

assert os.environ.get("MSB_REMOTE_AUDIT") == "1"
name = "audit-cli-" + uuid.uuid4().hex[:8]
report = Path(os.environ["MSB_AUDIT_REPORT"])
directory = report.parent / name
directory.mkdir()
report.with_suffix(".resources.json").write_text(json.dumps({"prefix": name}) + "\n")
rows = []
cli = os.environ["MSB_CLI"]
snapshot = None


def check(feature, args, expected="success", stdin=None, timeout=90):
    try:
        r = subprocess.run(
            [cli, "--remote", *args],
            input=stdin,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        message = r.stderr
        if feature in ("volume_inspect", "metrics", "fork", "cleanup-fork"):
            print(
                "DIAGNOSTIC "
                + feature
                + " "
                + message.replace(os.environ["MSB_API_KEY"], "[redacted]"),
                flush=True,
            )
        reason = (
            "config_projection"
            if "untagged enum CreateRequest" in message
            else "unsupported"
            if re.search(
                r"unsupported|not supported|local.only|only supported.*local|requires a local",
                message,
                re.IGNORECASE,
            )
            else "not_found"
            if re.search(r"404|not found", message, re.IGNORECASE)
            else "http_"
            + (m[0] if (m := re.search(r"\b[45]\d\d\b", message)) else "error")
        )
        verdict = (
            "PASS"
            if r.returncode == 0
            else ("UNSUPPORTED" if reason == "unsupported" else "FAIL")
        )
        if feature == "volume_inspect":
            # A remote volume has metadata but no path on the client's host.
            valid = (
                r.returncode == 0
                and name in r.stdout
                and "Kind:" in r.stdout
                and "Path:" not in r.stdout
            )
            verdict = "PASS" if valid else "FAIL"
        if expected == "not_found":
            verdict = "PASS" if r.returncode != 0 and reason == "not_found" else "FAIL"
        if expected == "unsupported":
            verdict = (
                "UNSUPPORTED"
                if r.returncode != 0 and reason == "unsupported"
                else "FAIL"
            )
        row = {"feature": feature, "verdict": verdict, "exit": r.returncode}
        if r.returncode:
            row["reason"] = reason
    except subprocess.TimeoutExpired:
        r = None
        row = {"feature": feature, "verdict": "FAIL", "reason": "timeout"}
    rows.append(row)
    print(json.dumps(row), flush=True)
    report.write_text(json.dumps({"sdk": "cli", "rows": rows}, indent=2) + "\n")
    return r


try:
    for feature, args in [
        ("context", ["context", "--format", "json"]),
        ("sandbox_list", ["list", "--format", "json"]),
        ("volume_list", ["volume", "list", "--format", "json"]),
        ("snapshot_list", ["snapshot", "list", "--format", "json"]),
        ("list_alias", ["sbx", "ls", "--format", "json"]),
    ]:
        check(feature, args)
    check("sandbox_missing", ["inspect", name + "-missing"], "not_found")
    check("volume_create", ["volume", "create", name])
    check("volume_inspect", ["volume", "inspect", name])
    r = check(
        "sandbox_create",
        ["create", "python", "--name", name, "--label", "audit=" + name],
        timeout=240,
    )
    if r is not None and r.returncode == 0:
        for feature, args in [
            ("status", ["status", name, "--format", "json"]),
            ("inspect", ["inspect", name]),
            ("ping", ["ping", name]),
            ("touch", ["touch", name]),
            ("metrics", ["metrics", name, "--format", "json"]),
            ("logs", ["logs", name, "--tail", "5"]),
            ("jobs", ["jobs", name, "--format", "json"]),
            (
                "modify_dry_run",
                ["modify", name, "--label", "audit=" + name, "--dry-run"],
            ),
            ("modify_labels", ["modify", name, "--label", "updated=true"]),
            ("exec", ["exec", name, "--no-stdin", "--", "printf", "cli-ok"]),
            ("exec_detached", ["exec", name, "--detach", "--", "sleep", "10"]),
        ]:
            check(feature, args)
        source = directory / "source"
        source.write_text("transfer-ok")
        check("copy_to_sandbox", ["copy", str(source), name + ":/tmp/audit-upload"])
        check(
            "copy_from_sandbox",
            ["copy", name + ":/tmp/audit-upload", str(directory / "output")],
        )
        if (directory / "output").exists():
            rows.append(
                {
                    "feature": "copy_bytes_verified",
                    "verdict": "PASS"
                    if (directory / "output").read_text() == "transfer-ok"
                    else "FAIL",
                }
            )
        for feature, args in [
            ("pause", ["pause", name]),
            ("resume", ["resume", name]),
            ("fork", ["fork", name, "--name", name + "-fork"]),
        ]:
            check(feature, args, "unsupported")
        check("stop", ["stop", name], timeout=420)
        check("wait_stopped", ["wait", name, "--timeout", "5s", "--format", "json"])
        r = check(
            "snapshot_create",
            ["snapshot", "create", name, "--sandbox", name],
            timeout=240,
        )
        if r is not None and r.returncode == 0:
            # Only consume a reference printed by this command, never list others' IDs.
            snapshot = r.stdout.strip().splitlines()[-1]
            for feature, args in [
                ("snapshot_inspect", ["snapshot", "inspect", snapshot]),
                ("snapshot_verify", ["snapshot", "verify", snapshot]),
                (
                    "snapshot_export",
                    ["snapshot", "export", snapshot, str(directory / "snapshot.msb")],
                ),
                ("snapshot_head", ["snapshot", "head", snapshot]),
            ]:
                check(feature, args)
            check(
                "snapshot_restore",
                ["snapshot", "restore", snapshot, "--name", name + "-restore"],
                timeout=240,
            )
            check(
                "restored_exec",
                ["exec", name + "-restore", "--no-stdin", "--", "printf", "restored"],
            )
        check(
            "snapshot_reindex", ["snapshot", "reindex", str(directory)], "unsupported"
        )
        empty = directory / "empty.msb"
        empty.write_bytes(b"")
        check("snapshot_import", ["snapshot", "import", str(empty)], "unsupported")
        check("start", ["start", name], timeout=240)
        check("restart", ["restart", name], timeout=420)
        check(
            "run",
            ["run", "--name", name + "-run", "python", "--", "printf", "run-ok"],
            timeout=240,
        )
finally:
    for suffix in ("-restore", "-run", "-fork", ""):
        # Missing is harmless cleanup, recorded distinctly from a successful mutation.
        r = check(
            "cleanup" + (suffix or "-sandbox"),
            ["remove", name + suffix, "--force", "--quiet"],
            timeout=420,
        )
        if (
            r is not None
            and r.returncode
            and re.search(r"404|not found", r.stderr, re.IGNORECASE)
        ):
            rows[-1]["verdict"] = "ABSENT"
        check(
            "cleanup_verified" + (suffix or "-sandbox"),
            ["inspect", name + suffix],
            "not_found",
        )
        if r is not None and r.returncode and rows[-1]["verdict"] == "PASS":
            rows[-2]["verdict"] = (
                "ABSENT"  # Quiet remove suppresses the missing-resource diagnostic.
            )
    if snapshot:
        check("snapshot_remove", ["snapshot", "remove", snapshot])
        check(
            "snapshot_cleanup_verified", ["snapshot", "inspect", snapshot], "not_found"
        )
    check("volume_remove", ["volume", "remove", name])
    check("volume_cleanup_verified", ["volume", "inspect", name], "not_found")
    report.write_text(json.dumps({"sdk": "cli", "rows": rows}, indent=2) + "\n")
raise SystemExit(any(r["verdict"] == "FAIL" for r in rows))
