#!/usr/bin/env python3
"""Run fixture-dependent SDK tests against matching CI artifacts, not an ambient home."""

import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time


CASES = (
    ("creation_progress_live", "restored_creation_progress_and_ignored_observer", None),
    ("eager_lifecycle_live", "portable_eager_forked_progress_and_stop_completion", None),
    ("eager_lifecycle_live", "eager_preparation_boundary_live", "delay"),
    ("eager_lifecycle_live", "eager_preparation_boundary_live", "error"),
    ("eager_lifecycle_live", "eager_preparation_boundary_live", "cancel"),
    # This case deliberately removes an unpinned backing. Run it after all consumers.
    ("creation_progress_live", "cancelled_backing_preparation_reaps_and_reconciles", None),
)


def test_command(archive, workspace, binary, test):
    return ["cargo-nextest", "nextest", "run", "--archive-file", str(archive),
            "--workspace-remap", str(workspace), "--run-ignored=only", "--test-threads", "1",
            "--no-tests", "fail", "-E", f"binary(={binary}) & test(={test})"]


def fixture_environment(home, binary, agent, firmware):
    env = dict(os.environ)
    for key in ("MSB_HOME", "MSB_BACKEND", "MSB_PROFILE", "MSB_CONFIG_PATH",
                "MSB_TEST_ISOLATE_HOME", "LD_PRELOAD", "MSB_TEST_EAGER_MODE",
                "MSB_TEST_EAGER_TRACE", "MSB_TEST_EAGER_PREFIX", "MSB_TEST_EAGER_DELAY_MS"):
        env.pop(key, None)
    env.update(MSB_HOME=str(home), MSB_BACKEND="local", MSB_PATH=str(binary),
               MSB_AGENTD_PATH=str(agent), MSB_LIBKRUNFW_PATH=str(firmware),
               MSB_PROGRESS_SNAPSHOT="ci-progress:baseline", NO_COLOR="1")
    return env


class Suite:
    def __init__(self, args):
        self.args = args
        self.output = args.output.resolve()
        self.output.mkdir(parents=True, exist_ok=False)
        # Short paths keep runtime Unix sockets below sockaddr_un's limit. The prefix
        # is also the destructive cancellation fixture's explicit ownership guard.
        self.home = Path(tempfile.mkdtemp(prefix="cbh-", dir="/tmp")) / "home"
        self.env = fixture_environment(self.home, args.binary, args.agent, args.firmware)
        self.records = []

    def run(self, label, command, env=None, timeout=180):
        started = time.monotonic()
        with (self.output / f"{label}.log").open("w") as log:
            # nextest has test-runner children. Reap its whole private process group
            # before catalog cleanup so a timed-out test cannot race a new VM create.
            with subprocess.Popen(command, cwd=self.home.parent, env=env or self.env,
                                  stdout=log, stderr=subprocess.STDOUT,
                                  start_new_session=True) as child:
                try:
                    returncode = child.wait(timeout=timeout)
                except (subprocess.TimeoutExpired, KeyboardInterrupt):
                    os.killpg(child.pid, signal.SIGTERM)
                    try:
                        child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(child.pid, signal.SIGKILL)
                        child.wait()
                    raise
        self.records.append(dict(case=label, returncode=returncode,
                                 seconds=round(time.monotonic() - started, 3)))
        (self.output / "results.json").write_text(json.dumps(
            dict(home=str(self.home), cases=self.records), indent=2) + "\n")
        print(json.dumps(self.records[-1]), flush=True)
        if returncode:
            raise subprocess.CalledProcessError(returncode, command)

    def msb(self, label, *args):
        self.run(label, [str(self.args.binary), *args])

    def inventory(self):
        result = subprocess.run([str(self.args.binary), "list", "--format", "json"],
                                cwd=self.home.parent, env=self.env, capture_output=True,
                                text=True, timeout=30, check=True)
        return json.loads(result.stdout)

    def cleanup(self):
        # The home was created here and never shared. Address its catalog names, never
        # signal bare historical PIDs that could have been reused by another process.
        errors = []
        for entry in self.inventory():
            if entry["status"] in ("Stopped", "Crashed"):
                continue
            try:
                self.msb("cleanup-" + entry["name"], "stop", entry["name"], "--force")
            except Exception as error:
                errors.append(str(error))
        resident = [entry for entry in self.inventory()
                    if entry["status"] not in ("Stopped", "Crashed")]
        if errors or resident:
            raise RuntimeError(f"fixture cleanup failed: {errors}; resident={resident}")

    def execute(self):
        try:
            self.msb("source", "create", self.args.image, "--name", "ci-source",
                     "--memory", "256M", "--max-memory", "256M", "--cpus", "1",
                     "--root-disk", "128M", "--tmpfs", "/work:16M", "--no-net")
            self.msb("checksum", "exec", "ci-source", "--", "sh", "-ec",
                     "dd if=/dev/urandom of=/work/payload bs=1M count=4; "
                     "sha256sum /work/payload > /work/hash")
            self.msb("capture", "snapshot", "create", "baseline", "--group", "ci-progress",
                     "--from-sandbox", "ci-source", "--full")
            self.msb("stop-source", "stop", "ci-source")
            self.msb("warm", "restore", self.env["MSB_PROGRESS_SNAPSHOT"],
                     "--name", "ci-warm", "--forked")
            self.msb("stop-warm", "stop", "ci-warm")
            self.msb("remove-warm", "remove", "ci-warm")
            shim = self.output / "slow-eager.so"
            self.run("compile-shim", ["cc", "-shared", "-fPIC", "-O2", "-o", str(shim),
                                     str(self.args.workspace / "scripts/smoke/cli/slow-eager-preload.c"),
                                     "-ldl"])
            failures = []
            for binary, test, mode in CASES:
                label = test + ("-" + mode if mode else "")
                env = dict(self.env)
                if mode:
                    env.update(LD_PRELOAD=str(shim), MSB_TEST_EAGER_MODE=mode,
                               MSB_TEST_EAGER_DELAY_MS=str({"delay": 15000, "error": 0,
                                                           "cancel": 45000}[mode]),
                               MSB_TEST_EAGER_TRACE=str(self.output / f"{label}.jsonl"),
                               MSB_TEST_EAGER_PREFIX=str(self.home))
                try:
                    self.run(label, test_command(self.args.archive, self.args.workspace,
                                                binary, test), env=env)
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
                    failures.append(str(error))
                    self.cleanup()
            if failures:
                raise RuntimeError("checkpoint fixture cases failed: " + "; ".join(failures))
        finally:
            self.cleanup()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("binary", "agent", "firmware", "archive", "workspace", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--image", default="mirror.gcr.io/library/alpine:3.20")
    args = parser.parse_args()
    for name in ("binary", "agent", "firmware", "archive", "workspace"):
        setattr(args, name, getattr(args, name).resolve(strict=True))

    def interrupted(_signal, _frame):
        raise KeyboardInterrupt("interrupted; disposing isolated fixture VMs")

    signal.signal(signal.SIGTERM, interrupted)
    Suite(args).execute()


if __name__ == "__main__":
    main()
