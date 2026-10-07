#!/usr/bin/env python3
"""Run managed-job VM tests with isolated, serial fixtures and matching CI artifacts."""

import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time


# Keep shutdown explicit and last. A VM-free coverage check compares this inventory to
# jobs.rs so adding a test cannot silently leave it outside the provisioned CI run.
CASES = (
    "managed_job_control_survives_resident_pause",
    "managed_job_lifetime_io_and_deadlines",
    "managed_job_options_logs_and_validation",
    "managed_job_input_backpressure_and_lease_heartbeat",
    "managed_job_bounds_rotation_and_pagination",
    "managed_job_z_blocked_input_signal",
    "managed_job_z_blocked_input_timeout",
    "exec_control_creation_backpressure_and_pause",
    "exec_stream_deadlines",
    "managed_job_zz_saturated_shutdown",
)


def fixture_environment(home, binary, agent, firmware):
    # Explicit artifacts and a private catalog must win over caller SDK, cloud,
    # fault-injection and per-test-home settings, including on self-hosted runners.
    env = {key: value for key, value in os.environ.items()
           if not key.startswith("MSB_") and key != "LD_PRELOAD"}
    env.update(MSB_HOME=str(home), MSB_BACKEND="local", MSB_PATH=str(binary),
               MSB_AGENTD_PATH=str(agent), MSB_LIBKRUNFW_PATH=str(firmware),
               LD_LIBRARY_PATH=str(firmware.parent), NO_COLOR="1")
    return env


def test_command(archive, workspace, test):
    return ["cargo-nextest", "nextest", "run", "--archive-file", str(archive),
            "--workspace-remap", str(workspace), "--run-ignored=only",
            "--test-threads", "1", "--no-tests", "fail",
            "-E", f"binary(=jobs) & test(={test})"]


class Suite:
    def __init__(self, args):
        self.args = args
        self.output = args.output.absolute()
        self.output.mkdir(parents=True, exist_ok=False)
        # Short paths avoid the Unix socket path limit; retain the catalog on failure
        # for diagnosis, but stop and remove its VMs before returning.
        self.root = Path(tempfile.mkdtemp(prefix="mjh-", dir="/tmp"))
        self.env = fixture_environment(self.root / "home", args.binary, args.agent, args.firmware)
        config = self.root / "config.json"
        config.write_text(json.dumps({"runtime": {"block_writeback": {
            "mode": "auto", "pool_mib": 4096}}}) + "\n")
        self.env["MSB_CONFIG_PATH"] = str(config)
        self.records = []

    def run(self, label, command, env=None, timeout=240):
        started = time.monotonic()
        record = dict(case=label, command=[str(arg) for arg in command])
        try:
            with (self.output / f"{label}.log").open("w") as log:
                with subprocess.Popen(command, cwd=self.root, env=env or self.env,
                                      stdout=log, stderr=subprocess.STDOUT,
                                      start_new_session=True) as child:
                    try:
                        record["returncode"] = child.wait(timeout=timeout)
                    except (subprocess.TimeoutExpired, KeyboardInterrupt):
                        # Stop nextest and its children before touching the fixture catalog.
                        os.killpg(child.pid, signal.SIGTERM)
                        try:
                            child.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            os.killpg(child.pid, signal.SIGKILL)
                            child.wait()
                        raise
            if record["returncode"]:
                raise subprocess.CalledProcessError(record["returncode"], command)
        except BaseException as error:
            record["error"] = str(error)
            raise
        finally:
            record["seconds"] = round(time.monotonic() - started, 3)
            self.records.append(record)
            (self.output / "results.json").write_text(json.dumps(
                dict(home=self.env["MSB_HOME"], cases=self.records), indent=2) + "\n")
            print(json.dumps(record), flush=True)

    def inventory(self):
        result = subprocess.run([str(self.args.binary), "list", "--format", "json"],
                                cwd=self.root, env=self.env, capture_output=True,
                                text=True, timeout=30, check=True)
        return json.loads(result.stdout)

    def cleanup(self, label):
        # Catalog ownership is private to this runner. Never kill a historical PID or
        # inspect the user's ambient home, even after a partial create or timed-out test.
        errors = []
        for entry in self.inventory():
            try:
                if entry["status"] not in ("Stopped", "Crashed"):
                    self.run(f"{label}-stop-{entry['name']}",
                             [str(self.args.binary), "stop", entry["name"], "--force"], timeout=45)
                self.run(f"{label}-remove-{entry['name']}",
                         [str(self.args.binary), "remove", entry["name"]], timeout=45)
            except (subprocess.SubprocessError, OSError) as error:
                errors.append(str(error))
        remaining = self.inventory()
        if errors or remaining:
            raise RuntimeError(f"managed-job fixture cleanup failed: {errors}; remaining={remaining}")

    def execute(self):
        cases = [] if self.args.python_only else [
            (name, test_command(self.args.archive, self.args.workspace, name)) for name in CASES]
        # managed-jobs.py invokes the real-terminal harness as well as CLI lifecycle
        # checks. Each CLI script gets a fresh VM, just like each Rust integration test.
        if not self.args.python_only:
            cases += [(name, [sys.executable, str(self.args.workspace / "scripts/smoke" / f"{name}.py")])
                      for name in ("managed-jobs", "managed-jobs-lifecycle")]
        if self.args.python:
            # Run the installed candidate wheel from the private fixture cwd. Supplying the
            # sandbox environment below makes this opt-in regression execute instead of skip.
            cases.append(("python-managed-jobs", [str(self.args.python), "-m", "pytest",
                          "--import-mode=importlib", "-q", str(self.args.workspace /
                          "sdk/python/tests/test_jobs_integration.py")]))
        failures = []
        try:
            for index, (label, command) in enumerate(cases):
                env = dict(self.env, MSB_JOB_TEST_SANDBOX=f"ci-jobs-{index}")
                if label in ("managed_job_zz_saturated_shutdown", "managed-jobs"):
                    env["MSB_JOB_TEST_RESTART"] = "1"
                try:
                    self.run(label + "-create", [str(self.args.binary), "create", self.args.image,
                             "--name", env["MSB_JOB_TEST_SANDBOX"], "--memory", "512M",
                             "--cpus", "1", "--root-disk", "128M"], env=env)
                    self.run(label, command, env=env)
                except (subprocess.SubprocessError, OSError) as error:
                    failures.append(f"{label}: {error}")
                finally:
                    # Cleanup failure aborts the suite: continuing would violate the
                    # otherwise-idle-VM requirement and consume unbounded host resources.
                    self.cleanup(label)
            if failures:
                raise RuntimeError("managed-job fixture cases failed: " + "; ".join(failures))
        finally:
            self.cleanup("final")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("binary", "agent", "firmware", "workspace", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--python", type=Path)
    parser.add_argument("--python-only", action="store_true")
    parser.add_argument("--image", default="mirror.gcr.io/library/alpine:3.20")
    args = parser.parse_args()
    if args.python_only and not args.python:
        parser.error("--python-only requires --python")
    if not args.python_only and not args.archive:
        parser.error("--archive is required unless --python-only is selected")
    for name in ("binary", "agent", "firmware", "archive", "workspace", "python"):
        if getattr(args, name) is None:
            continue
        setattr(args, name, getattr(args, name).absolute())
        if not getattr(args, name).exists():
            parser.error(f"{name} does not exist: {getattr(args, name)}")

    def interrupted(_signal, _frame):
        raise KeyboardInterrupt("interrupted; disposing isolated fixture VMs")

    signal.signal(signal.SIGTERM, interrupted)
    Suite(args).execute()


if __name__ == "__main__":
    main()
