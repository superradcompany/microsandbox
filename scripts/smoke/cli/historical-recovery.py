#!/usr/bin/env python3
"""Kill/recover real legacy-descriptor migrations and verify recovered guest contents.

This qualifies the 0.6.0/0.6.6 manifest.json family through actual production
migration functions in a test executable. Pause hooks are absent from shipped
binaries. It does not qualify CLI binary/database rollback or every archive format.
"""

import argparse
from contextlib import suppress
import importlib.util
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import tempfile
import time


spec = importlib.util.spec_from_file_location(
    "historical_snapshots", Path(__file__).with_name("historical-snapshots.py"))
history = importlib.util.module_from_spec(spec)
spec.loader.exec_module(history)
WORKER = "backend::local::snapshot::historical_recovery_tests::historical_recovery_worker"
BOUNDARIES = {
    "upgrade": ("planned", "descriptor_published", "index_published", "legacy_retired"),
    "downgrade": ("planned", "canonical_backed_up", "legacy_descriptor_published",
                  "legacy_index_published", "canonical_retired"),
}


def worker_environment(root, action, phase=None):
    env = {key: value for key, value in os.environ.items()
           if not key.startswith("MSB_") and key not in ("LD_PRELOAD", "DYLD_INSERT_LIBRARIES")}
    env.update(MSB_TEST_HISTORICAL_ROOT=str(root), MSB_TEST_HISTORICAL_ACTION=action)
    if phase:
        env["MSB_TEST_HISTORICAL_BOUNDARY"] = phase
    return env


def reap(child):
    with suppress(ProcessLookupError):
        os.killpg(child.pid, signal.SIGKILL)
    child.wait()


def run_worker(binary, root, action, output, phase=None, timeout=120):
    """A kill pass requires the matching durable marker and an actual SIGKILL exit."""
    command = [str(binary), "--exact", WORKER, "--ignored", "--nocapture"]
    marker = root / "boundary.json"
    marker.unlink(missing_ok=True)
    (root / "boundary-ready").unlink(missing_ok=True)
    (root / "result.json").unlink(missing_ok=True)
    with output.open("w") as log, subprocess.Popen(
            command, env=worker_environment(root, action, phase), stdin=subprocess.DEVNULL,
            stdout=log, stderr=subprocess.STDOUT, start_new_session=True) as child:
        try:
            if phase:
                deadline = time.monotonic() + timeout
                while not marker.exists():
                    if child.poll() is not None:
                        raise RuntimeError(f"worker exited before {action}/{phase}; see {output}")
                    if time.monotonic() >= deadline:
                        raise TimeoutError(f"worker did not reach {action}/{phase}")
                    time.sleep(0.01)
                # Creation precedes the durable flush by a few instructions. The worker
                # publishes a second marker after fsync before it parks.
                ready = root / "boundary-ready"
                while not ready.exists():
                    if child.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError("boundary marker was not durably acknowledged")
                    time.sleep(0.01)
                observation = json.loads(marker.read_text())
                if observation != {"pid": child.pid, "action": action, "phase": phase}:
                    raise RuntimeError("crash marker does not identify the selected worker phase")
                reap(child)
                if child.returncode != -signal.SIGKILL:
                    raise RuntimeError("worker was not terminated by SIGKILL")
                return {"command": command, "exit": child.returncode, "boundary": observation}
            code = child.wait(timeout=timeout)
            if code:
                raise RuntimeError(f"{action} worker failed with {code}; see {output}")
            return json.loads((root / "result.json").read_text())
        except BaseException:
            reap(child)
            raise


def migration_state(root):
    """Audit the actual surviving journal/index immediately after process death."""
    with sqlite3.connect(f"file:{root / 'migration.db'}?mode=ro", uri=True) as database:
        integrity = database.execute("PRAGMA integrity_check").fetchall()
        if integrity != [("ok",)]:
            raise RuntimeError(f"migration database integrity failed: {integrity}")
        return {
            "index": database.execute(
                "SELECT digest, migration_state FROM snapshot_index ORDER BY artifact_path").fetchall(),
            "journal": database.execute(
                "SELECT kind, phase, error_code FROM snapshot_artifact_migration ORDER BY kind, artifact_path").fetchall(),
        }


def recovered_bytes(original, artifact, action):
    expected = (original / "manifest.json").read_bytes()
    descriptor = artifact / (".manifest.json.legacy" if action == "upgrade" else "manifest.json")
    if descriptor.read_bytes() != expected:
        raise RuntimeError("exact original legacy descriptor was not retained")
    if history.digest(artifact / "upper.ext4") != history.digest(original / "upper.ext4"):
        raise RuntimeError("recovery changed the historical disk payload")
    if action == "downgrade" and (artifact / "snapshot.json").exists():
        raise RuntimeError("completed downgrade left a canonical descriptor")


def catalog_empty(home):
    with sqlite3.connect(f"file:{home / 'db/msb.db'}?mode=ro", uri=True) as database:
        return database.execute("SELECT COUNT(*) FROM sandbox").fetchone()[0] == 0


def qualify(args):
    args.output.mkdir(parents=True, exist_ok=False)
    fixture = json.loads((args.fixture / "fixture.json").read_text())
    originals = args.fixture / "originals"
    before = history.inventory(originals)
    if (fixture["status"] != "produced" or fixture["producer_version"] not in ("0.6.0", "0.6.6")
            or before != fixture["originals"]):
        raise RuntimeError("qualification requires an unchanged produced 0.6.0/0.6.6 fixture")
    if history.digest(args.legacy_binary) != fixture["binary_sha256"]:
        raise RuntimeError("legacy reader does not match the recorded producer binary")
    listing = subprocess.check_output(
        [str(args.test_binary), "--list"], text=True, timeout=30,
        env=worker_environment(args.output, "list"))
    if f"{WORKER}: test" not in listing.splitlines():
        raise RuntimeError("test executable lacks the historical recovery driver")
    home = Path(tempfile.mkdtemp(prefix="msb-hr-", dir=args.temp_root)).resolve()
    candidate = history.Runner(args.candidate, history.environment(
        args.candidate, args.firmware, home, args.agent), args.output / "candidate")
    report = {"status": "running", "producer_version": fixture["producer_version"], "home": str(home),
              "candidate_sha256": history.digest(args.candidate),
              "test_binary_sha256": history.digest(args.test_binary),
              "legacy_binary_sha256": history.digest(args.legacy_binary),
              "firmware_sha256": history.digest(args.firmware),
              "agent": history.agent_identity(args.agent),
              "agent_sha256": history.digest(args.agent),
              "harness_sha256": history.digest(Path(__file__)), "cases": [],
              "originals_unchanged": False}
    try:
        # Seed only the image cache through a genuine historical archive. Recovered directory
        # launches use their own private copies and never this seed group's descriptor.
        candidate.run("seed-image", "snapshot", "load", "cache-seed", "--file", originals / "fixture.msb")
        for action, phases in BOUNDARIES.items():
            for phase in phases:
                label = action + "-" + phase
                case = args.output / label
                case.mkdir()
                root = Path(tempfile.mkdtemp(prefix="msb-hw-", dir=args.temp_root)).resolve()
                (root / "snapshots").mkdir()
                artifact = root / "snapshots/artifact"
                history.copy_artifact(originals / "artifact", artifact)
                row = {"action": action, "phase": phase, "root": str(root), "status": "running"}
                sandbox = "recovery-" + str(len(report["cases"]))
                create_attempted = False
                try:
                    if action == "downgrade":
                        row["setup"] = run_worker(args.test_binary, root, "upgrade", case / "setup.log")
                    row["killed"] = run_worker(args.test_binary, root, action, case / "killed.log", phase)
                    row["after_kill"] = migration_state(root)
                    row["recovered"] = run_worker(args.test_binary, root, action, case / "recovery.log")
                    recovered_bytes(originals / "artifact", artifact, action)
                    recovered = history.inventory(artifact)
                    row["retry"] = run_worker(args.test_binary, root, action, case / "retry.log")
                    if history.inventory(artifact) != recovered:
                        raise RuntimeError("successful retry changed recovered artifact bytes")
                    if row["retry"]["index"] != row["recovered"]["index"]:
                        raise RuntimeError("successful retry changed recovered index identity")
                    row["after_retry"] = migration_state(root)
                    if action == "downgrade":
                        legacy_home = root / "legacy-home"
                        legacy = history.Runner(args.legacy_binary, history.environment(
                            args.legacy_binary, args.firmware, legacy_home), case / "legacy")
                        legacy.run("inspect", "snapshot", "inspect", artifact, "--verify")
                        if history.inventory(artifact) != recovered:
                            raise RuntimeError("legacy inspection changed recovered artifact bytes")
                    # Restore from a copy so current automatic migration does not change
                    # the exact downgraded artifact whose old-reader compatibility we checked.
                    launch = root / "launch"
                    history.copy_artifact(artifact, launch)
                    # A failed create can still leave state to clean up. Earlier worker
                    # failures never dispatched create and must not invent cleanup failures.
                    create_attempted = True
                    candidate.run(label + "-create", "create", "--name", sandbox,
                                  "--from-snapshot", launch, "--pull", "never")
                    candidate.run(label + "-guest", "exec", sandbox, "--", "sh", "-ec",
                                  history.VERIFY + "\nprintf recovery-write > /root/historical/recovery-write; sync")
                    candidate.run(label + "-stop", "stop", sandbox)
                    candidate.run(label + "-restart", "start", sandbox)
                    candidate.run(label + "-persistent", "exec", sandbox, "--", "sh", "-ec",
                                  "test $(cat /root/historical/recovery-write) = recovery-write; " + history.VERIFY)
                    row["status"] = "passed"
                except BaseException as error:
                    row["status"], row["error"] = "failed", str(error)
                    if not isinstance(error, Exception):
                        raise
                finally:
                    history.finish_case(candidate, label, sandbox, row, report,
                                        args.output, attempted=create_attempted)
        report["catalog_empty"] = catalog_empty(home)
        if any(row["status"] != "passed" for row in report["cases"]) or not report["catalog_empty"]:
            raise RuntimeError("one or more recovery cases or final cleanup failed")
        report["status"] = "passed"
    except BaseException as error:
        report["status"], report["error"] = "failed", str(error)
        raise
    finally:
        history.finish_originals(report, originals, before, args.output)
    if report["status"] != "passed":
        raise RuntimeError("original artifacts changed during recovery qualification")


def main():
    history.install_termination_handler()
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("fixture", "candidate", "test-binary", "legacy-binary", "firmware", "agent", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--temp-root", type=Path, default=Path("/tmp"))
    args = parser.parse_args()
    for name, value in vars(args).items():
        if isinstance(value, Path):
            setattr(args, name, value.resolve())
    qualify(args)


if __name__ == "__main__":
    main()
