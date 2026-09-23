#!/usr/bin/env python3
"""Small live snapshot/branch regression suite; no benchmark repetitions or shared VM state."""

import argparse
from contextlib import closing, contextmanager
import csv
import io
import json
import os
from pathlib import Path
import signal
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time


REPOSITORY = Path(__file__).resolve().parents[3]


def positive_seconds(value):
    seconds = float(value)
    if not 0 < seconds < float("inf"):
        raise argparse.ArgumentTypeError("timeout must be finite and positive")
    return seconds


def output_text(value):
    # TimeoutExpired carries bytes even when subprocess.run requested text output.
    return value.decode(errors="replace") if isinstance(value, bytes) else value or ""


@contextmanager
def defer_interrupts():
    # A second Ctrl-C/SIGTERM must not abandon the remaining bounded stop attempts.
    received = []
    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        for sig in previous:
            signal.signal(sig, lambda signum, _frame: received.append(signum))
        yield received
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


class Smoke:
    def __init__(self, args):
        self.args = args
        self.binary = args.binary.expanduser().resolve(strict=True)
        if not self.binary.is_file() or not os.access(self.binary, os.X_OK):
            raise ValueError(f"msb binary is not executable: {self.binary}")
        if args.output:
            self.root = args.output.expanduser().resolve()
            self.root.mkdir(mode=0o700, parents=True, exist_ok=False)
        else:
            # macOS's default per-user temp path is too long for the runtime's Unix sockets.
            self.root = Path(tempfile.mkdtemp(prefix="msb-smoke-", dir="/tmp" if os.name == "posix" else None))
        self.logs = self.root / "logs"
        self.logs.mkdir()
        self.home = self.root / "home"
        # Never borrow the caller's catalog, cloud backend, project config, or VM names.
        # Explicit matching runtime/firmware overrides remain available to development builds.
        self.env = dict(os.environ)
        for key in ("MSB_HOME", "MSB_CONFIG_PATH", "MSB_BACKEND", "MSB_PROFILE"):
            self.env.pop(key, None)
        self.env.update(MSB_HOME=str(self.home), MSB_BACKEND="local", NO_COLOR="1")
        self.names = []
        self.active = []
        self.deadline = None
        self.report = {
            "status": "running", "binary": str(self.binary), "home": str(self.home),
            "layout": args.layout, "image": args.image, "commands": [], "cleanup": [],
            "setup_ms": 0, "operations_ms": 0, "cleanup_ms": 0,
        }
        self.persist()

    def persist(self):
        (self.root / "report.json").write_text(json.dumps(self.report, indent=2) + "\n")

    def run(self, case, *arguments, expected_failure=False, phase="operations", timeout=None):
        limit = self.args.timeout if timeout is None else timeout
        if phase == "operations" and self.deadline is not None:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError(f"suite deadline exceeded before {case}")
            limit = min(limit, remaining)
        command = [str(self.binary), *map(str, arguments)]
        started = time.monotonic()
        stdout, stderr, code, timed_out = "", "", None, False
        try:
            result = subprocess.run(command, env=self.env, cwd=self.root, capture_output=True,
                                    text=True, encoding="utf-8", errors="replace", timeout=limit)
            stdout, stderr, code = result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired as error:
            stdout, stderr = output_text(error.stdout), output_text(error.stderr)
            timed_out = True
        finally:
            elapsed = round((time.monotonic() - started) * 1000, 2)
            prefix = f"{len(self.report['commands']):03d}-{case}"
            # Preserve replacement characters from partial/invalid timeout output even on
            # Windows hosts whose default text encoding cannot represent them.
            (self.logs / f"{prefix}.stdout.log").write_text(stdout, encoding="utf-8")
            (self.logs / f"{prefix}.stderr.log").write_text(stderr, encoding="utf-8")
            row = dict(case=case, phase=phase, argv=command[1:], ms=elapsed, exit=code,
                       expected_failure=expected_failure, timed_out=timed_out)
            self.report["commands"].append(row)
            self.persist()
            print(f"{case}: {elapsed:.2f} ms (exit={code})", flush=True)
        if timed_out:
            raise RuntimeError(f"{case} timed out after {limit:.2f}s")
        # A crash is not proof that a deliberately unsupported operation was refused cleanly.
        if code is None or code < 0 or code > 255 or (code != 0) != expected_failure:
            raise RuntimeError(f"{case} failed (exit={code}): {stderr[-2000:]}")
        return stdout.strip(), stderr.strip()

    def guest(self, case, name, script):
        return self.run(case, "exec", name, "--", "sh", "-ec", script)[0]

    def remember(self, name):
        # Register before create/branch: a timed-out client may have started a detached VM.
        self.names.append(name)
        self.active.append(name)

    def create(self, name, *options):
        self.remember(name)
        self.run("create-" + name, "create", "--name", name, *options)

    def branch(self, source, child):
        self.remember(child)
        self.run("branch-" + child, "branch", source, "--name", child)

    def restore(self, name, snapshot, *options):
        self.remember(name)
        self.run("restore-" + name, "restore", snapshot, "--name", name, *options)

    def stop(self, name):
        self.run("stop-" + name, "stop", name, "--timeout", "5")
        self.active.remove(name)

    def check_markers(self, name, value, ram=True):
        script = "cat /smoke-marker; " + (
            "cat /dev/shm/smoke-marker" if ram else "test ! -e /dev/shm/smoke-marker")
        actual = self.guest("markers-" + name, name, script)
        expected = value + "\n" + value if ram else value
        if actual != expected:
            raise RuntimeError(f"{name}: expected {expected!r}, got {actual!r}")

    def check_status(self, name, expected):
        entries = json.loads(self.run("status-" + name, "list", "--format", "json")[0])
        actual = {entry["name"]: entry["status"] for entry in entries}.get(name)
        if actual != expected:
            raise RuntimeError(f"{name}: expected status {expected}, got {actual}")

    def capture(self, member, full=False):
        options = ["--full"] if full else []
        output = self.run("capture-" + member, "snapshot", "create", member,
                          "--from-sandbox", "source", "--group", "work", *options)[0]
        path = Path(output.splitlines()[-1])
        descriptor = json.loads((path / "snapshot.json").read_text())
        if (path.parent != self.home / "snapshots/work"
                or path.name != descriptor["snapshot_id"]
                or descriptor["state"]["kind"] != ("checkpoint" if full else "file")):
            raise RuntimeError(f"unexpected captured artifact: {path}")
        return descriptor

    def exercise(self):
        layout = "flat:512M" if self.args.layout == "flat" else "512M"
        self.create("source", self.args.image, "--root-disk", layout,
                    "--memory", "256M", "--cpus", "2")
        self.guest("seed-source", "source",
                   "echo source > /smoke-marker; echo source > /dev/shm/smoke-marker; sync")
        before = set((self.home / "snapshots").rglob("snapshot.json"))
        self.branch("source", "child")
        self.check_markers("child", "source")
        self.guest("write-private-child", "child",
                   "echo child > /smoke-marker; echo child > /dev/shm/smoke-marker")
        self.check_markers("source", "source")
        self.branch("child", "grandchild")
        self.check_markers("grandchild", "child")
        if before != set((self.home / "snapshots").rglob("snapshot.json")):
            raise RuntimeError("direct branching installed a durable snapshot")
        _, error = self.run("duplicate-child-refused", "branch", "source", "--name", "child",
                            expected_failure=True)
        if "already exists" not in error.lower():
            raise RuntimeError(f"duplicate branch failed for an unrelated reason: {error}")
        self.check_markers("child", "child")
        self.stop("child")
        self.check_markers("grandchild", "child")
        self.stop("grandchild")

        self.run("pause-source", "pause", "source")
        self.check_status("source", "Paused")
        self.branch("source", "paused-child")
        self.check_markers("paused-child", "source")
        self.stop("paused-child")
        full = self.capture("full", full=True)
        self.check_status("source", "Paused")
        _, error = self.run("paused-exec-refused", "exec", "source", "--", "true",
                            expected_failure=True)
        if "paused" not in error.lower():
            raise RuntimeError(f"paused exec failed for an unrelated reason: {error}")
        self.run("resume-source", "resume", "source")
        self.check_markers("source", "source")

        # A full snapshot preserves tmpfs; disk-only cold boot must not restore it.
        disk = self.capture("disk")
        self.check_status("source", "Running")
        if disk["parent"] != full["snapshot_id"]:
            raise RuntimeError("capture lineage was not retained")
        self.restore("disk-child", "work:disk")
        self.check_markers("disk-child", "source", ram=False)
        self.stop("disk-child")

        full_archive, disk_archive = self.root / "full.msb", self.root / "disk.msb"
        self.run("save-full", "snapshot", "save", "work:full", full_archive)
        self.run("save-disk", "snapshot", "save", "work:disk", disk_archive)
        self.run("load-batch-reversed", "snapshot", "load", disk_archive, full_archive,
                 "--group", "received")
        head = json.loads(self.run("batch-head", "snapshot", "head", "received",
                                   "--format", "json")[0])
        if head["head"] != disk["snapshot_id"]:
            raise RuntimeError("batch head followed argument order instead of ancestry")
        self.run("verify-imported-full", "snapshot", "verify", "received:full")
        self.restore("eager", "received:full")
        self.check_markers("eager", "source")
        self.run("pause-eager", "pause", "eager")
        _, error = self.run("paused-stop-refused", "stop", "eager", "--timeout", "5",
                            expected_failure=True)
        if "paused" not in error.lower():
            raise RuntimeError("paused stop failed without explaining the paused state")
        self.check_status("eager", "Paused")
        self.run("resume-eager", "resume", "eager")
        self.stop("eager")

        before = set((self.home / "snapshots").rglob("snapshot.json"))
        self.restore("forked", full_archive, "--forked")
        if before != set((self.home / "snapshots").rglob("snapshot.json")):
            raise RuntimeError("direct archive restore installed an intermediate snapshot")
        # Unlink only archives created by this test, after the child is ready.
        full_archive.unlink()
        disk_archive.unlink()
        self.check_markers("forked", "source")
        self.guest("write-private-forked", "forked",
                   "echo forked > /smoke-marker; echo forked > /dev/shm/smoke-marker")
        self.check_markers("source", "source")
        self.stop("source")
        self.check_markers("forked", "forked")
        self.stop("forked")

    def runtime_pids(self):
        # The CLI catalog can become terminal before the host process has exited. Read only
        # this test's private run history, including VMs stopped earlier in the suite.
        database = self.home / "db/msb.db"
        if not database.exists():
            return []
        # A sqlite connection's own context manager only ends the transaction; it does
        # not close the handle. Windows refuses fixture deletion while it remains open.
        with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True, timeout=2)) as db:
            pids = sorted({row[0] for row in db.execute('SELECT pid FROM "run" WHERE pid > 0')})
        remaining = []
        for pid in pids:
            if os.name == "nt":
                result = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                                        capture_output=True, text=True, timeout=2, check=True)
                alive = any(len(row) > 1 and row[1] == str(pid)
                            for row in csv.reader(io.StringIO(result.stdout)))
            else:
                result = subprocess.run(["ps", "-p", str(pid), "-o", "stat="],
                                        capture_output=True, text=True, timeout=2)
                if result.returncode not in (0, 1):
                    raise RuntimeError(f"could not inspect runtime PID {pid}: {result.stderr}")
                alive = bool(result.stdout.strip()) and not result.stdout.strip().startswith("Z")
            if alive:
                remaining.append(pid)
        # Never signal bare recorded PIDs: PID reuse must not endanger another process.
        return remaining

    def cleanup(self):
        with defer_interrupts() as interrupted:
            errors = self.cleanup_owned()
        if interrupted:
            errors.append("interrupted during cleanup; completed bounded stop attempts")
        return errors

    def cleanup_owned(self):
        errors = []
        for name in reversed(self.active):
            try:
                self.run("cleanup-" + name, "stop", name, "--timeout", "5",
                         phase="cleanup", timeout=10)
                self.report["cleanup"].append(dict(name=name, stopped=True))
            except Exception as error:
                # A failed create may not have a catalog row. Preserve those diagnostics, then
                # check both the catalog and process history after a bounded force-stop attempt.
                self.report["cleanup"].append(dict(name=name, error=str(error)))
                try:
                    self.run("force-stop-" + name, "stop", name, "--force",
                             phase="cleanup", timeout=10)
                except Exception as forced:
                    errors.append(str(forced))
        try:
            entries = json.loads(self.run("cleanup-inventory", "list", "--format", "json",
                                          phase="cleanup", timeout=10)[0])
            resident = [entry for entry in entries if entry["status"] not in ("Stopped", "Crashed")]
            self.report["remaining_sandboxes"] = resident
            if resident:
                errors.append(f"test sandboxes remain resident: {resident}")
        except Exception as error:
            errors.append(f"could not verify VM cleanup: {error}")
        try:
            deadline = time.monotonic() + 5
            while True:
                remaining = self.runtime_pids()
                if not remaining or time.monotonic() >= deadline:
                    break
                time.sleep(0.1)
            self.report["remaining_runtime_pids"] = remaining
            if remaining:
                errors.append(f"recorded runtime PIDs are still alive: {remaining}")
        except Exception as error:
            errors.append(f"could not verify runtime process exit: {error}")
        return errors

    def execute(self):
        started = time.monotonic()
        failure = None
        operations_started = None
        try:
            # Build/download/materialization time is not snapshot latency. Preparing both layouts
            # also avoids deferred image work becoming part of the first measured create.
            self.run("prepare-image", "pull", self.args.image, "--materialize", "all",
                     phase="setup", timeout=180)
            self.report["setup_ms"] = round((time.monotonic() - started) * 1000, 2)
            operations_started = time.monotonic()
            self.deadline = operations_started + self.args.suite_timeout
            self.exercise()
        except (Exception, KeyboardInterrupt) as error:
            failure = str(error) or "interrupted"
        finally:
            if operations_started is not None:
                self.report["operations_ms"] = round(
                    (time.monotonic() - operations_started) * 1000, 2)
            else:
                self.report["setup_ms"] = round((time.monotonic() - started) * 1000, 2)
            cleanup_started = time.monotonic()
            # Cleanup is independent of the expired operation deadline and tries every owned VM.
            cleanup_errors = self.cleanup()
            if failure or cleanup_errors:
                for name in self.names:
                    try:
                        self.run("diagnostics-" + name, "logs", "--source", "system", name,
                                 phase="diagnostics", timeout=5)
                    except Exception:
                        # Diagnostics are best-effort and must not mask the original failure.
                        pass
            self.report["home_removed"] = False
            if not failure and not cleanup_errors and self.home.exists():
                # This home was created beneath our exclusive output directory. Once both
                # catalog and process checks pass, retain text evidence, not large RAM/disks.
                try:
                    shutil.rmtree(self.home)
                    self.report["home_removed"] = True
                except OSError as error:
                    cleanup_errors.append(f"could not remove owned test home: {error}")
            self.report.update(
                status="failed" if failure or cleanup_errors else "passed", error=failure,
                cleanup_errors=cleanup_errors,
                cleanup_ms=round((time.monotonic() - cleanup_started) * 1000, 2),
                total_ms=round((time.monotonic() - started) * 1000, 2),
            )
            self.persist()
        print(json.dumps({key: self.report[key] for key in
                          ("status", "setup_ms", "operations_ms", "cleanup_ms", "total_ms")}),
              flush=True)
        print(f"Report: {self.root / 'report.json'}", flush=True)
        if self.report["error"] or self.report["cleanup_errors"]:
            print(self.report["error"] or "; ".join(self.report["cleanup_errors"]), file=sys.stderr)
        return 0 if self.report["status"] == "passed" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path,
                        default=REPOSITORY / "build" / ("msb.exe" if os.name == "nt" else "msb"))
    parser.add_argument("--output", type=Path, help="New directory for an isolated home and logs")
    parser.add_argument("--layout", choices=("managed", "flat"), default="managed")
    parser.add_argument("--image", default="mirror.gcr.io/library/alpine:3.20")
    parser.add_argument("--timeout", type=positive_seconds, default=30,
                        help="Per-operation timeout in seconds (default: 30)")
    parser.add_argument("--suite-timeout", type=positive_seconds, default=120,
                        help="Operation-suite deadline, excluding image setup/cleanup (default: 120)")
    args = parser.parse_args()

    def interrupted(_signum, _frame):
        raise KeyboardInterrupt("interrupted; cleaning up owned test VMs")

    signal.signal(signal.SIGTERM, interrupted)
    try:
        return Smoke(args).execute()
    except (OSError, ValueError) as error:
        parser.exit(1, f"snapshot smoke: {error}\n")


if __name__ == "__main__":
    sys.exit(main())
