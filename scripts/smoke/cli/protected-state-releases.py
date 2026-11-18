#!/usr/bin/env python3
"""Verify actual old CLI catalog admission and direct runtime rejection guards.

--releases is a JSON object mapping labels such as "msb 0.6.18" to binary paths.
Use disposable --output and select matching firmware/agent through the normal environment.
"""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sqlite3


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--releases", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    home = output / "home"
    env = dict(os.environ, MSB_HOME=str(home), MSB_BACKEND="local", MSB_PATH=str(args.binary.resolve()))
    subprocess.run([str(args.binary.resolve()), "list"], env=env, check=True, capture_output=True, timeout=30)
    # A real catalog row and a canary make removal/start refusal observable.
    with sqlite3.connect(home / "db/msb.db") as database:
        database.execute("INSERT INTO sandbox (id,name,config,status,ephemeral) VALUES (1,'guard','{}','Stopped',0)")
        database.execute("INSERT INTO protected_sandbox_state VALUES (1,1)")
    storage = home / "sandboxes/guard"
    storage.mkdir(parents=True)
    canary = storage / "root-disk.json"
    canary.write_bytes(b"protected host authority canary")
    fixture_path = Path(__file__).resolve().parents[3] / "crates/runtime/tests/fixtures/launch-v0.6.18.json"
    fixture = json.loads(fixture_path.read_text())
    results = []
    for label, executable in json.loads(args.releases.read_text()).items():
        case = output / label.replace(" ", "-")
        runtime = case / "runtime"
        runtime.mkdir(parents=True)
        (case / "logs").mkdir()
        (runtime / "heartbeat.json").mkdir()
        guard = b'{"schema":"microsandbox.upgrade-required/protected-state"}\n'
        (runtime / "root-disk.json").write_bytes(guard)
        config = dict(fixture, runtime_dir=str(runtime), log_dir=str(case / "logs"),
                      db_path=str(case / "unused.db"), sandboxes_dir=str(output),
                      run_dir=str(case / "run"), cpu_lease_dir=str(case / "cpu"),
                      writeback_lease_dir=str(case / "writeback"), agent_sock=str(case / "agent.sock"),
                      network=None, libkrunfw_path=os.environ["MSB_LIBKRUNFW_PATH"])
        legacy = "0.6." in label
        if legacy:
            config.update(env=[], workdir=None)
        else:
            config["execution"] = "boot"
        launch = case / "launch.json"
        launch.write_text(json.dumps(config))
        command = [executable, "sandbox" if legacy else "machine", "--name", "guard",
                   "--sandbox-id", "1", "--config-file", str(launch)]
        run = subprocess.run(command, env=dict(env, MSB_HOME=str(case / "isolated-home")),
                             text=True, capture_output=True, timeout=30)
        logs = run.stdout + run.stderr + "\n".join(
            path.read_text(errors="replace") for path in (case / "logs").iterdir() if path.is_file())
        (case / "runtime.log").write_text(logs)
        # Historical binaries cannot display a new error string. Verify their actual
        # heartbeat or journal decoder rejection, rather than counting any failure.
        rejected = run.returncode != 0 and (
            "Is a directory" in logs or "parse root-disk state: missing field" in logs)
        assert (runtime / "root-disk.json").read_bytes() == guard
        assert (runtime / "heartbeat.json").is_dir()
        results.append(dict(release=label, operation="direct-runtime", passed=rejected))
        commands = [("list",), ("start", "guard"), ("remove", "guard"), ("snapshot", "list")]
        if not legacy:
            commands += [("modify", "guard", "--root-disk", "320M"), ("modify", "guard", "--compact")]
        for command in commands:
            run = subprocess.run([executable, *command], env=dict(env, MSB_PATH=executable),
                                 text=True, capture_output=True, timeout=30)
            (case / ("-".join(command) + ".log")).write_text(run.stdout + run.stderr)
            results.append(dict(release=label, operation=" ".join(command), passed=(
                run.returncode != 0 and (
                    "database schema is newer" in run.stderr.lower() or
                    "Migration file of version 'm20261030_000001_protected_sandbox_state' is missing" in run.stderr))))
            assert canary.read_bytes() == b"protected host authority canary"
        (output / "results.json").write_text(json.dumps(results, indent=2))
        print(label, "PASS" if all(r["passed"] for r in results if r["release"] == label) else "FAIL", flush=True)
    assert all(row["passed"] for row in results), "see results.json for failed release cases"


if __name__ == "__main__":
    main()
