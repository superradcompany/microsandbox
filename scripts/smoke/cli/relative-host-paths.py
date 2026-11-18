"""Check that a stopped sandbox keeps its original bind sources after changing cwd.

Requires virtualization, matching firmware, and network access to pull Alpine.
Uses an isolated MSB_HOME and removes only its own sandboxes. Logs remain in --out.
"""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sqlite3
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--msb", required=True)
    parser.add_argument("--firmware", required=True)
    parser.add_argument("--legacy-msb", required=True, help="Older release used to create saved state")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    binary = str(Path(args.msb).resolve())
    legacy_binary = str(Path(args.legacy_msb).resolve())
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=False)
    # Keep Unix socket names short, and avoid macOS's /tmp symlink in mount roots.
    home = Path(tempfile.mkdtemp(prefix="msb-paths-", dir=None if os.name == "nt" else "/tmp")).resolve()
    (out / "home.txt").write_text(str(home))
    config = home / "config.json"
    config.write_text("{}")
    env = {key: value for key, value in os.environ.items() if not key.startswith("MSB_")}
    env.update(
        MSB_HOME=str(home),
        MSB_PATH=binary,
        MSB_CONFIG_PATH=str(config),
        MSB_LIBKRUNFW_PATH=str(Path(args.firmware).resolve()),
    )
    first, second = home / "a", home / "b"
    for directory, marker in [(first, "original"), (second, "wrong")]:
        (directory / "work").mkdir(parents=True)
        (directory / "work" / "marker").write_text(marker)
        (directory / "config.txt").write_text(marker + "-file")

    def run(*command, cwd=first, check=True, executable=binary):
        result = subprocess.run(
            [executable, *command], cwd=cwd, env={**env, "MSB_PATH": executable},
            stdin=subprocess.DEVNULL, text=True,
            capture_output=True, timeout=180,
        )
        evidence = dict(binary=executable, command=list(command), cwd=str(cwd), code=result.returncode,
                        stdout=result.stdout, stderr=result.stderr)
        with (out / "commands.jsonl").open("a") as log:
            log.write(json.dumps(evidence) + "\n")
        if check and result.returncode:
            raise AssertionError(evidence)
        return result

    name = "relative-paths"
    legacy_name = "legacy-relative-paths"
    try:
        # Produce saved state with the old release instead of manufacturing a
        # new-format fixture. Create it before the new binary upgrades the catalog:
        # an older binary must not be asked to write a newer database schema.
        # Restart must neither prompt nor rewrite the sandbox's saved configuration.
        run("create", "alpine:3.21", "--name", legacy_name,
            "--mount-dir", "./work:/workspace", "--mount-file", "./config.txt:/config.txt",
            executable=legacy_binary)
        run("exec", legacy_name, "--", "sh", "-c", "echo retained > /legacy-data",
            executable=legacy_binary)
        run("stop", legacy_name, executable=legacy_binary)
        with sqlite3.connect(home / "db" / "msb.db") as db:
            saved_legacy = db.execute("SELECT config FROM sandbox WHERE name = ?",
                                      (legacy_name,)).fetchone()[0]
        legacy = json.loads(saved_legacy)
        sources = {mount["guest"]: mount["host"] for mount in legacy["mounts"]
                   if mount["type"] == "Bind"}
        assert not Path(sources["/workspace"]).is_absolute(), sources
        assert not Path(sources["/config.txt"]).is_absolute(), sources
        run("create", "alpine:3.21", "--name", name,
            "--mount-dir", "./work:/workspace", "--mount-file", "./config.txt:/config.txt")
        # Inspect the actual persisted configuration, not just launch arguments.
        inspected = json.loads(run("inspect", name, "--format", "json").stdout)
        (out / "inspect.json").write_text(json.dumps(inspected, indent=2))
        for config_key in ["config", "active_config"]:
            sources = {mount["guest"]: mount["host"]
                       for mount in inspected[config_key]["mounts"] if mount["type"] == "Bind"}
            assert sources["/workspace"] == str(first / "work"), inspected
            assert sources["/config.txt"] == str(first / "config.txt"), inspected
        run("stop", name)
        result = run("exec", name, "--", "sh", "-c",
                     "cat /workspace/marker; echo; cat /config.txt", cwd=second)
        assert result.stdout.strip() == "original\noriginal-file", result

        # If the original source disappears, startup must fail rather than use
        # the same relative name from the new working directory.
        run("stop", name, cwd=second)
        (first / "work").rename(first / "held")
        try:
            result = run("exec", name, "--", "cat", "/workspace/marker", cwd=second, check=False)
            assert result.returncode != 0, result
            assert "wrong" not in result.stdout, result
        finally:
            (first / "held").rename(first / "work")
        for directory, marker in [(first, "original"), (second, "wrong")]:
            result = run("exec", legacy_name, "--", "sh", "-c",
                         "cat /workspace/marker; echo; cat /config.txt; echo; cat /legacy-data",
                         cwd=directory)
            assert result.stdout.strip() == f"{marker}\n{marker}-file\nretained", result
            run("stop", legacy_name, cwd=directory)
            with sqlite3.connect(home / "db" / "msb.db") as db:
                stored = db.execute("SELECT config FROM sandbox WHERE name = ?",
                                    (legacy_name,)).fetchone()[0]
            assert stored == saved_legacy, (stored, saved_legacy)
        assert (first / "work" / "marker").read_text() == "original"
        assert (second / "work" / "marker").read_text() == "wrong"
        print("PASS: new paths stay anchored; old saved paths and guest data retain legacy behavior")
    finally:
        run("stop", name, check=False)
        run("rm", name, "--force", check=False)
        run("stop", legacy_name, check=False)
        run("rm", legacy_name, "--force", check=False)


if __name__ == "__main__":
    main()
